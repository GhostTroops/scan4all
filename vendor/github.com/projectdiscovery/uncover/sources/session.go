package sources

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/retryablehttp-go"
	errorutil "github.com/projectdiscovery/utils/errors"
)

// DefaultRateLimits of all/most of sources are hardcoded by default to improve performance
// engine is not present in default ratelimits then user given ratelimit from cli options is used
var DefaultRateLimits = map[string]*ratelimit.Options{
	"shodan":     {Key: "shodan", MaxCount: 1, Duration: time.Second},
	"shodan-idb": {Key: "shodan-idb", MaxCount: 1, Duration: time.Second},
	"fofa":       {Key: "fofa", MaxCount: 1, Duration: time.Second},
	"censys":     {Key: "censys", MaxCount: 1, Duration: 3 * time.Second},
	"quake":      {Key: "quake", MaxCount: 1, Duration: time.Second},
	"hunter":     {Key: "hunter", MaxCount: 15, Duration: time.Second},
	"zoomeye":    {Key: "zoomeye", MaxCount: 1, Duration: time.Second},
	"netlas":     {Key: "netlas", MaxCount: 1, Duration: time.Second},
	"criminalip": {Key: "criminalip", MaxCount: 1, Duration: time.Second},
	"publicwww":  {Key: "publicwww", MaxCount: 1, Duration: time.Minute},
	"hunterhow":  {Key: "hunterhow", MaxCount: 1, Duration: 3 * time.Second},
}

// Session handles session agent sessions
type Session struct {
	Keys       *Keys
	Client     *retryablehttp.Client
	RetryMax   int
	RateLimits *ratelimit.MultiLimiter
}

func NewSession(keys *Keys, retryMax, timeout, rateLimit int, engines []string, duration time.Duration) (*Session, error) {
	Transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ResponseHeaderTimeout: time.Duration(timeout) * time.Second,
		Proxy:                 http.ProxyFromEnvironment,
	}

	httpclient := &http.Client{
		Transport: Transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	options := retryablehttp.Options{RetryMax: retryMax}
	options.RetryWaitMax = time.Duration(timeout) * time.Second
	client := retryablehttp.NewWithHTTPClient(httpclient, options)

	session := &Session{
		Client:   client,
		Keys:     keys,
		RetryMax: retryMax,
	}

	var defaultRatelimit *ratelimit.Options
	switch {
	case rateLimit > 0:
		defaultRatelimit = &ratelimit.Options{Key: "default", MaxCount: uint(rateLimit), Duration: duration}
	default:
		defaultRatelimit = &ratelimit.Options{IsUnlimited: true, Key: "default"}
	}

	var err error
	session.RateLimits, err = ratelimit.NewMultiLimiter(context.Background(), defaultRatelimit)
	if err != nil {
		return nil, err
	}

	// setup ratelimit of all engines
	for _, engine := range engines {
		rateLimitOpts := DefaultRateLimits[engine]
		if rateLimitOpts == nil {
			// fallback to using default ratelimit
			rateLimitOpts = defaultRatelimit
			rateLimitOpts.Key = engine
		}
		if err = session.RateLimits.Add(rateLimitOpts); err != nil {
			return nil, errorutil.NewWithErr(err).Msgf("failed to setup ratelimit of %v got %v", engine, err)
		}
	}

	return session, nil
}

func (s *Session) Do(request *retryablehttp.Request, source string) (*http.Response, error) {
	err := s.RateLimits.Take(source)
	if err != nil {
		return nil, err
	}
	// close request connection (does not reuse connections)
	request.Close = true
	resp, err := s.Client.Do(request)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		requestURL, _ := url.QueryUnescape(request.URL.String())
		return resp, fmt.Errorf("unexpected status code %d received from %s", resp.StatusCode, requestURL)
	}
	return resp, nil
}
