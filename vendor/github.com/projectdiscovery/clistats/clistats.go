package clistats

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/freeport"
	errorutil "github.com/projectdiscovery/utils/errors"
)

// StatisticsClient is an interface implemented by a statistics client.
//
// A unique ID is to be provided along with a description for the field to be
// displayed as output.
//
// Multiple types of statistics are provided like Counters as well as static
// fields which display static information only.
//
// A metric cannot be added once the client has been started. An
// error will be returned if the metric cannot be added. Already existing fields
// of same names are overwritten.
type StatisticsClient interface {
	// Start starts the event loop of the stats client.
	Start() error
	// Stop stops the event loop of the stats client
	Stop() error

	// AddCounter adds a uint64 counter field to the statistics client.
	//
	// A counter is used to track an increasing quantity, like requests,
	// errors etc.
	AddCounter(id string, value uint64)

	// GetCounter returns the current value of a counter.
	GetCounter(id string) (uint64, bool)

	// IncrementCounter increments the value of a counter by a count.
	IncrementCounter(id string, count int)

	// AddStatic adds a static information field to the statistics.
	//
	// The value for these metrics will remain constant throughout the
	// lifecycle of the statistics client. All the values will be
	// converted into string and displayed as such.
	AddStatic(id string, value interface{})

	// GetStatic returns the original value for a static field.
	GetStatic(id string) (interface{}, bool)

	// AddDynamic adds a dynamic field to display whose value
	// is retrieved by running a callback function.
	//
	// The callback function performs some actions and returns the value
	// to display. Generally this is used for calculating requests per
	// seconds, elapsed time, etc.
	AddDynamic(id string, Callback DynamicCallback)

	// GetDynamic returns the dynamic field callback for data retrieval.
	GetDynamic(id string) (DynamicCallback, bool)

	//GetStatResponse returns '/metrics' response for a given interval
	GetStatResponse(interval time.Duration, callback func(string, error) error)
}

// DynamicCallback is called during statistics calculation for a dynamic
// field.
//
// The value returned from this callback is displayed as the current value
// of a dynamic field. This can be utilised to calculate things like elapsed
// time, requests per seconds, etc.
type DynamicCallback func(client StatisticsClient) interface{}

// Statistics is a client for showing statistics on the stdout.
type Statistics struct {
	Options *Options
	ctx     context.Context
	cancel  context.CancelFunc

	// counters is a list of counters for the client. These can only
	// be accessed concurrently via atomic operations and once the main
	// event loop has started must not be modified.
	counters map[string]*atomic.Uint64

	// static contains a list of static counters for the client.
	static map[string]interface{}

	// dynamic contains a list of dynamic metrics for the client.
	dynamic map[string]DynamicCallback

	httpServer *http.Server
}

var _ StatisticsClient = (*Statistics)(nil)

// New creates a new statistics client for cli stats printing with default options
func New() (*Statistics, error) {
	return NewWithOptions(context.Background(), &DefaultOptions)
}

// NewWithOptions creates a new client with custom options
func NewWithOptions(ctx context.Context, options *Options) (*Statistics, error) {
	ctx, cancel := context.WithCancel(ctx)

	statistics := &Statistics{
		Options:  options,
		ctx:      ctx,
		cancel:   cancel,
		counters: make(map[string]*atomic.Uint64),
		static:   make(map[string]interface{}),
		dynamic:  make(map[string]DynamicCallback),
	}
	return statistics, nil
}

// Start starts the event loop of the stats client.
func (s *Statistics) Start() error {
	if s.Options.Web {
		http.HandleFunc("/metrics", func(w http.ResponseWriter, req *http.Request) {
			items := make(map[string]interface{})
			for k, v := range s.counters {
				items[k] = v.Load()
			}
			for k, v := range s.static {
				items[k] = v
			}
			for k, v := range s.dynamic {
				items[k] = v(s)
			}

			// Common fields
			requests, hasRequests := s.GetCounter("requests")
			startedAt, hasStartedAt := s.GetStatic("startedAt")
			total, hasTotal := s.GetCounter("total")
			var (
				duration    time.Duration
				hasDuration bool
			)
			// duration
			if hasStartedAt {
				if stAt, ok := startedAt.(time.Time); ok {
					duration = time.Since(stAt)
					items["duration"] = FmtDuration(duration)
					hasDuration = true
				}
			}
			// rps
			if hasRequests && hasDuration {
				items["rps"] = String(uint64(float64(requests) / duration.Seconds()))
			}
			// percent
			if hasRequests && hasTotal {
				percentData := (float64(requests) * float64(100)) / float64(total)
				percent := String(uint64(percentData))
				items["percent"] = percent
			}

			data, err := jsoniter.Marshal(items)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(fmt.Sprintf(`{"error":"%s"}`, err)))
				return
			}
			_, _ = w.Write(data)
		})

		// check if the default port is available
		port, err := freeport.GetPort(freeport.TCP, "127.0.0.1", s.Options.ListenPort)
		if err != nil {
			// otherwise picks a random one and update the options
			port, err = freeport.GetFreeTCPPort("127.0.0.1")
			if err != nil {
				return err
			}
			s.Options.ListenPort = port.Port
		}

		s.httpServer = &http.Server{
			Addr:    fmt.Sprintf("%s:%d", port.Address, port.Port),
			Handler: http.DefaultServeMux,
		}

		go func() {
			_ = s.httpServer.ListenAndServe()
		}()
	}
	return nil
}

// GetStatResponse returns '/metrics' response for a given interval
func (s *Statistics) GetStatResponse(interval time.Duration, callback func(string, error) error) {
	metricCallback := func(url string) (string, error) {
		response, err := http.Get(url)
		if err != nil {
			return "", errorutil.New("Error getting /metrics response: %v", err)
		}
		defer func() {
			_ = response.Body.Close()
		}()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return "", errorutil.New("Error reading /metrics response body: %v", err)
		}
		return string(body), nil
	}

	url := fmt.Sprintf("http://127.0.0.1:%v/metrics", s.Options.ListenPort)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				if err := callback(metricCallback(url)); err != nil {
					return
				}
			}
		}
	}()
}

// Stop stops the event loop of the stats client
func (s *Statistics) Stop() error {
	s.cancel()
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(context.Background()); err != nil {
			return err
		}
	}
	return nil
}
