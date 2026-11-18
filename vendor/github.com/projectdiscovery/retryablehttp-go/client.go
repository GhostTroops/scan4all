package retryablehttp

import (
	"net/http"
	"sync/atomic"
	"time"
)

// Client is used to make HTTP requests. It adds additional functionality
// like automatic retries to tolerate minor outages.
type Client struct {
	// HTTPClient is the internal HTTP client (http1x + http2 via connection upgrade upgrade).
	HTTPClient *http.Client
	// HTTPClient2 is a copy of HTTPClient that attempts native http2 at transport level, used as fallback
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
	// WrapTransport wraps the underlying [http.RoundTripper].
	// The function receives the default transport (with fastdialer, TLS config)
	// and should return the transport to use.
	// Applied to both HTTP/1.1 and HTTP/2 clients.
	WrapTransport func(http.RoundTripper) http.RoundTripper
	// Trace enables tracing of the HTTP request
	Trace bool
	// TLSSessionCacheSize specifies the size of the TLS session cache.
	//
	// If less than or equal to zero, defaults to 1024.
	TLSSessionCacheSize int
}

// DefaultOptionsSpraying contains the default options for host spraying
// scenarios where lots of requests need to be sent to different hosts.
var DefaultOptionsSpraying = Options{
	RetryWaitMin:        1 * time.Second,
	RetryWaitMax:        30 * time.Second,
	Timeout:             30 * time.Second,
	RetryMax:            5,
	RespReadLimit:       4096,
	KillIdleConn:        true,
	NoAdjustTimeout:     true,
	TLSSessionCacheSize: 1024,
}

// DefaultOptionsSingle contains the default options for host bruteforce
// scenarios where lots of requests need to be sent to a single host.
var DefaultOptionsSingle = Options{
	RetryWaitMin:        1 * time.Second,
	RetryWaitMax:        30 * time.Second,
	Timeout:             30 * time.Second,
	RetryMax:            5,
	RespReadLimit:       4096,
	KillIdleConn:        false,
	NoAdjustTimeout:     true,
	TLSSessionCacheSize: 1024,
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

	if options.HttpClient == nil && options.TLSSessionCacheSize > 0 {
		applyTLSSessionCache(httpclient, options.TLSSessionCacheSize)
	}

	// Derive the HTTP/2 fallback client from httpclient so both send requests
	// the same way. This must happen before WrapTransport hides the
	// *http.Transport that newHTTP2Client clones.
	httpclient2, err := newHTTP2Client(httpclient)
	if err != nil {
		return nil
	}

	// Apply transport wrapper if provided
	if options.WrapTransport != nil {
		httpclient.Transport = options.WrapTransport(httpclient.Transport)
		httpclient2.Transport = options.WrapTransport(httpclient2.Transport)
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
