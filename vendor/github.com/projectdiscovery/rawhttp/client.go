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
		options.FastDialer, err = fastdialer.NewDialer(fastdialer.DefaultOptions)
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
	protocol := "http"
	if strings.HasPrefix(strings.ToLower(url), "https://") {
		protocol = "https"
	}

	if headers == nil {
		headers = make(map[string][]string)
	}
	u, err := urlutil.ParseURL(url, true)
	if err != nil {
		return nil, err
	}

	host := u.Host
	if options.AutomaticHostHeader {
		// add automatic space
		headers["Host"] = []string{fmt.Sprintf(" %s", host)}
	}

	if !strings.Contains(host, ":") {
		if protocol == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

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

	if strings.HasPrefix(url, "https://") {
		protocol = "https"
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
		return nil, err
	}
	resp, err := conn.ReadResponse(options.ForceReadAllBody)
	if err != nil {
		return nil, err
	}

	r, err := toHTTPResponse(conn, resp)
	if err != nil {
		return nil, err
	}

	if resp.Status.IsRedirect() && redirectstatus.FollowRedirects && redirectstatus.Current <= redirectstatus.MaxRedirects {
		// consume the response body
		_, err := io.Copy(io.Discard, r.Body)
		if err := firstErr(err, r.Body.Close()); err != nil {
			return nil, err
		}
		loc := headerValue(r.Header, "Location")
		if strings.HasPrefix(loc, "/") {
			loc = fmt.Sprintf("%s://%s%s", protocol, host, loc)
		}
		redirectstatus.Current++
		return c.do(method, loc, uripath, headers, body, redirectstatus, options)
	}

	return r, err
}

// RedirectStatus is the current redirect status for the request
type RedirectStatus struct {
	FollowRedirects bool
	MaxRedirects    int
	Current         int
}
