package retryablehttp

import (
	"net/http"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// Client is used to make HTTP requests. It adds additional functionality
// like automatic retries to tolerate minor outages.
type Client struct {
	// HTTPClient is the internal HTTP client (http1x + http2 via connection upgrade upgrade).
	HTTPClient *http.Client
	// HTTPClient is the internal HTTP client configured to fallback to native http2 at transport level
	HTTPClient2 *http.Client

	requestCounter atomic.Uint32

	// RequestLogHook allows a user-supplied function to be called
	// before each retry.
	RequestLogHook RequestLogHook
	// ResponseLogHook allows a user-supplied function to be called
	// with the response from each HTTP request executed.
	ResponseLogHook ResponseLogHook
	// ErrorHandler specifies the custom error handler to use, if any
	ErrorHandler ErrorHandler

	// CheckRetry specifies the policy for handling retries, and is called
	// after each request. The default policy is DefaultRetryPolicy.
	CheckRetry CheckRetry
	// Backoff specifies the policy for how long to wait between retries
	Backoff Backoff

	options Options
}

// Options contains configuration options for the client
type Options struct {
	// RetryWaitMin is the minimum time to wait for retry
	RetryWaitMin time.Duration
	// RetryWaitMax is the maximum time to wait for retry
	RetryWaitMax time.Duration
	// Timeout is the maximum time to wait for the request
	Timeout time.Duration
	// RetryMax is the maximum number of retries
	RetryMax int
	// RespReadLimit is the maximum HTTP response size to read for
	// connection being reused.
	RespReadLimit int64
	// Verbose specifies if debug messages should be printed
	Verbose bool
	// KillIdleConn specifies if all keep-alive connections gets killed
	KillIdleConn bool
	// Custom CheckRetry policy
	CheckRetry CheckRetry
	// Custom Backoff policy
	Backoff Backoff
	// NoAdjustTimeout disables automatic adjustment of HTTP request timeout
	NoAdjustTimeout bool
	// Custom http client
	HttpClient *http.Client
}

// DefaultOptionsSpraying contains the default options for host spraying
// scenarios where lots of requests need to be sent to different hosts.
var DefaultOptionsSpraying = Options{
	RetryWaitMin:    1 * time.Second,
	RetryWaitMax:    30 * time.Second,
	Timeout:         30 * time.Second,
	RetryMax:        5,
	RespReadLimit:   4096,
	KillIdleConn:    true,
	NoAdjustTimeout: true,
}

// DefaultOptionsSingle contains the default options for host bruteforce
// scenarios where lots of requests need to be sent to a single host.
var DefaultOptionsSingle = Options{
	RetryWaitMin:    1 * time.Second,
	RetryWaitMax:    30 * time.Second,
	Timeout:         30 * time.Second,
	RetryMax:        5,
	RespReadLimit:   4096,
	KillIdleConn:    false,
	NoAdjustTimeout: true,
}

// NewClient creates a new Client with default settings.
func NewClient(options Options) *Client {
	var httpclient *http.Client
	if options.HttpClient != nil {
		httpclient = options.HttpClient
	} else if options.KillIdleConn {
		httpclient = DefaultClient()
	} else {
		httpclient = DefaultPooledClient()
	}

	httpclient2 := DefaultClient()
	if err := http2.ConfigureTransport(httpclient2.Transport.(*http.Transport)); err != nil {
		return nil
	}

	var retryPolicy CheckRetry
	var backoff Backoff

	retryPolicy = DefaultRetryPolicy()
	if options.CheckRetry != nil {
		retryPolicy = options.CheckRetry
	}

	backoff = DefaultBackoff()
	if options.Backoff != nil {
		backoff = options.Backoff
	}

	// add timeout to clients
	if options.Timeout > 0 {
		httpclient.Timeout = options.Timeout
		httpclient2.Timeout = options.Timeout
	}

	// if necessary adjusts per-request timeout proportionally to general timeout (30%)
	if options.Timeout > time.Second*15 && options.RetryMax > 1 && !options.NoAdjustTimeout {
		httpclient.Timeout = time.Duration(options.Timeout.Seconds()*0.3) * time.Second
	}

	c := &Client{
		HTTPClient:  httpclient,
		HTTPClient2: httpclient2,
		CheckRetry:  retryPolicy,
		Backoff:     backoff,
		options:     options,
	}

	c.setKillIdleConnections()
	return c
}

// NewWithHTTPClient creates a new Client with custom http client
// Deprecated: Use options.HttpClient
func NewWithHTTPClient(client *http.Client, options Options) *Client {
	options.HttpClient = client
	return NewClient(options)
}

// setKillIdleConnections sets the kill idle conns switch in two scenarios
//  1. If the http.Client has settings that require us to do so.
//  2. The user has enabled it by default, in which case we have nothing to do.
func (c *Client) setKillIdleConnections() {
	if c.HTTPClient != nil || !c.options.KillIdleConn {
		if b, ok := c.HTTPClient.Transport.(*http.Transport); ok {
			c.options.KillIdleConn = b.DisableKeepAlives || b.MaxConnsPerHost < 0
		}
	}
}
