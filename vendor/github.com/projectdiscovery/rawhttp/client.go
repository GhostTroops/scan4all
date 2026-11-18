package rawhttp

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
	urlutil "github.com/projectdiscovery/utils/url"
)

// Client is a client for making raw http requests with go
type Client struct {
	dialer  Dialer
	Options *Options
}

// AutomaticHostHeader sets Host header for requests automatically
func AutomaticHostHeader(enable bool) {
	DefaultClient.Options.AutomaticHostHeader = enable
}

// AutomaticContentLength performs automatic calculation of request content length.
func AutomaticContentLength(enable bool) {
	DefaultClient.Options.AutomaticContentLength = enable
}

// NewClient creates a new rawhttp client with provided options
func NewClient(options *Options) *Client {
	client := &Client{
		dialer:  new(dialer),
		Options: options,
	}
	if options.FastDialer == nil {
		var err error
		opts := fastdialer.DefaultOptions
		opts.DialerTimeout = options.Timeout
		options.FastDialer, err = fastdialer.NewDialer(opts)
		if err != nil {
			gologger.Error().Msgf("Could not create fast dialer: %s\n", err)
		}
	}
	return client
}

// Head makes a HEAD request to a given URL
func (c *Client) Head(url string) (*http.Response, error) {
	return c.DoRaw("HEAD", url, "", nil, nil)
}

// Get makes a GET request to a given URL
func (c *Client) Get(url string) (*http.Response, error) {
	return c.DoRaw("GET", url, "", nil, nil)
}

// Post makes a POST request to a given URL
func (c *Client) Post(url string, mimetype string, body io.Reader) (*http.Response, error) {
	headers := make(map[string][]string)
	headers["Content-Type"] = []string{mimetype}
	return c.DoRaw("POST", url, "", headers, body)
}

// Do sends a http request and returns a response
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	method := req.Method
	headers := req.Header
	url := req.URL.String()
	body := req.Body

	return c.DoRaw(method, url, "", headers, body)
}

// Dor sends a retryablehttp request and returns the response
func (c *Client) Dor(req *retryablehttp.Request) (*http.Response, error) {
	method := req.Method
	headers := req.Header
	url := req.URL.String()
	body := req.Body

	return c.DoRaw(method, url, "", headers, body)
}

// DoRaw does a raw request with some configuration
func (c *Client) DoRaw(method, url, uripath string, headers map[string][]string, body io.Reader) (*http.Response, error) {
	redirectstatus := &RedirectStatus{
		FollowRedirects: true,
		MaxRedirects:    c.Options.MaxRedirects,
	}
	return c.do(method, url, uripath, headers, body, redirectstatus, c.Options)
}

// DoRawWithOptions performs a raw request with additional options
func (c *Client) DoRawWithOptions(method, url, uripath string, headers map[string][]string, body io.Reader, options *Options) (*http.Response, error) {
	redirectstatus := &RedirectStatus{
		FollowRedirects: options.FollowRedirects,
		MaxRedirects:    c.Options.MaxRedirects,
	}
	return c.do(method, url, uripath, headers, body, redirectstatus, options)
}

// Close closes client and any resources it holds
func (c *Client) Close() {
	if c.Options.FastDialer != nil {
		c.Options.FastDialer.Close()
	}
}

func (c *Client) getConn(protocol, host string, options *Options) (Conn, error) {
	if options.Proxy != "" {
		return c.dialer.DialWithProxy(protocol, host, c.Options.Proxy, c.Options.ProxyDialTimeout, options)
	}
	var conn Conn
	var err error
	if options.Timeout > 0 {
		conn, err = c.dialer.DialTimeout(protocol, host, options.Timeout, options)
	} else {
		conn, err = c.dialer.Dial(protocol, host, options)
	}
	return conn, err
}

func (c *Client) do(method, url, uripath string, headers map[string][]string, body io.Reader, redirectstatus *RedirectStatus, options *Options) (*http.Response, error) {
	if headers == nil {
		headers = make(map[string][]string)
	}
	u, err := urlutil.ParseURL(url, true)
	if err != nil {
		return nil, err
	}

	if options.AutomaticHostHeader {
		// add automatic space
		headers["Host"] = []string{" " + u.Host}
	}

	protocol, host := dialTarget(url, u.Host)

	// standard path
	path := u.Path
	if path == "" {
		path = "/"
	}
	if !u.Params.IsEmpty() {
		path += "?" + u.Params.Encode()
	}
	// override if custom one is specified
	if uripath != "" {
		path = uripath
	}

	conn, err := c.getConn(protocol, host, options)
	if err != nil {
		return nil, err
	}

	req := toRequest(method, path, nil, headers, body, options)
	req.AutomaticContentLength = options.AutomaticContentLength
	req.AutomaticHost = options.AutomaticHostHeader

	// set timeout if any
	if options.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(options.Timeout))
	}

	if err := conn.WriteRequest(req); err != nil {
		_ = conn.Close()
		return nil, err
	}
	resp, err := conn.ReadResponse(options.ForceReadAllBody)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	r, err := toHTTPResponse(conn, resp)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	follow := redirectstatus.FollowRedirects || options.FollowHostRedirects
	if resp.Status.IsRedirect() && follow && redirectstatus.Current <= redirectstatus.MaxRedirects {
		loc := headerValue(r.Header, "Location")
		if strings.HasPrefix(loc, "/") {
			loc = fmt.Sprintf("%s://%s%s", protocol, host, loc)
		}

		if options.FollowHostRedirects && !dialsTo(loc, protocol, host) {
			return r, nil
		}
		// consume the response body
		_, err := io.Copy(io.Discard, r.Body)
		if err := firstErr(err, r.Body.Close()); err != nil {
			return nil, err
		}
		redirectstatus.Current++
		return c.do(method, loc, uripath, headers, body, redirectstatus, options)
	}

	return r, err
}

// dialTarget returns the protocol and the host:port address that a request
// to rawURL connects to, given host, the host parsed from rawURL.
func dialTarget(rawURL, host string) (string, string) {
	protocol, port := "http", ":80"
	if strings.HasPrefix(strings.ToLower(rawURL), "https://") {
		protocol, port = "https", ":443"
	}

	if strings.Contains(host, ":") {
		return protocol, host
	}

	return protocol, host + port
}

// dialsTo reports whether a request to rawURL connects to addr over protocol.
// The address must match exactly: case folding would also equate distinct
// hostnames, such as "ſecret.com" and "secret.com".
func dialsTo(rawURL, protocol, addr string) bool {
	u, err := urlutil.ParseURL(rawURL, true)
	if err != nil {
		return false
	}

	p, a := dialTarget(rawURL, u.Host)

	return p == protocol && a == addr
}

// RedirectStatus is the current redirect status for the request
type RedirectStatus struct {
	FollowRedirects bool
	MaxRedirects    int
	Current         int
}
