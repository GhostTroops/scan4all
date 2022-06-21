package clistats

import (
	"bufio"
	"context"
	"os"
	"time"

	"go.uber.org/atomic"
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
	Start(printer PrintCallback, tickDuration time.Duration) error
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
}

// DynamicCallback is called during statistics calculation for a dynamic
// field.
//
// The value returned from this callback is displayed as the current value
// of a dynamic field. This can be utilised to calculated things like elapsed
// time, requests per seconds, etc.
type DynamicCallback func(client StatisticsClient) interface{}

// Statistics is a client for showing statistics on the stdout.
type Statistics struct {
	ctx    context.Context
	cancel context.CancelFunc
	ticker tickerInterface
	events chan rune

	// counters is a list of counters for the client. These can only
	// be accessed concurrently via atomic operations and once the main
	// event loop has started must not be modified.
	counters map[string]*atomic.Uint64

	// static contains a list of static counters for the client.
	static map[string]interface{}

	// dynamic contains a lsit of dynamic metrics for the client.
	dynamic map[string]DynamicCallback

	// printer is the printing callback for data display
	printer PrintCallback
}

// PrintCallback is used by clients to build and display a string on the screen.
type PrintCallback func(client StatisticsClient)

var _ StatisticsClient = (*Statistics)(nil)

// New creates a new statistics client for cli stats printing.
func New() (*Statistics, error) {
	ctx, cancel := context.WithCancel(context.Background())

	return &Statistics{
		ctx:      ctx,
		cancel:   cancel,
		counters: make(map[string]*atomic.Uint64),
		static:   make(map[string]interface{}),
		dynamic:  make(map[string]DynamicCallback),
	}, nil
}

// Start starts the event loop of the stats client.
func (s *Statistics) Start(printer PrintCallback, tickDuration time.Duration) error {
	s.printer = printer

	s.events = make(chan rune)
	s.internalRead()

	go s.eventLoop(tickDuration)
	return nil
}

// eventLoop is the event loop listening for keyboard events as well as
// looking out for cancellation attempts.
func (s *Statistics) eventLoop(tickDuration time.Duration) {
	if tickDuration != -1 {
		s.ticker = &ticker{t: time.NewTicker(tickDuration)}
	} else {
		s.ticker = &noopTicker{tick: make(chan time.Time)}
	}

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.ticker.Tick():
			s.printer(s)
		case event := <-s.events:
			if event == '\x03' {
				s.Stop()
				kill()
				return
			}
			s.printer(s)
		}
	}
}

func (s *Statistics) internalRead() {
	go func() {
		in := bufio.NewReader(os.Stdin)
		for {
			select {
			case <-s.ctx.Done():
				close(s.events)
				return
			default:
				r, _, err := in.ReadRune()
				if err != nil {
					continue
				}
				s.events <- r
			}
		}
	}()
}

// Stop stops the event loop of the stats client
func (s *Statistics) Stop() error {
	s.cancel()
	if s.ticker != nil {
		s.ticker.Stop()
	}
	return nil
}
