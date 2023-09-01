package retryablehttp

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"net/url"
	"os"

	readerutil "github.com/projectdiscovery/utils/reader"
	urlutil "github.com/projectdiscovery/utils/url"
)

// When True . Request uses `http` as scheme instead of `https`
var PreferHTTP bool

// Request wraps the metadata needed to create HTTP requests.
// Request is not threadsafe. A request cannot be used by multiple goroutines
// concurrently.
type Request struct {
	// Embed an HTTP request directly. This makes a *Request act exactly
	// like an *http.Request so that all meta methods are supported.
	*http.Request

	//URL
	*urlutil.URL

	// Metrics contains the metrics for the request.
	Metrics Metrics

	Auth *Auth
}

// Metrics contains the metrics about each request
type Metrics struct {
	// Failures is the number of failed requests
	Failures int
	// Retries is the number of retries for the request
	Retries int
	// DrainErrors is number of errors occured in draining response body
	DrainErrors int
}

// Auth specific information
type Auth struct {
	Type     AuthType
	Username string
	Password string
}

type AuthType uint8

const (
	DigestAuth AuthType = iota
)

// RequestLogHook allows a function to run before each retry. The HTTP
// request which will be made, and the retry number (0 for the initial
// request) are available to users. The internal logger is exposed to
// consumers.
type RequestLogHook func(*http.Request, int)

// ResponseLogHook is like RequestLogHook, but allows running a function
// on each HTTP response. This function will be invoked at the end of
// every HTTP request executed, regardless of whether a subsequent retry
// needs to be performed or not. If the response body is read or closed
// from this method, this will affect the response returned from Do().
type ResponseLogHook func(*http.Response)

// ErrorHandler is called if retries are expired, containing the last status
// from the http library. If not specified, default behavior for the library is
// to close the body and return an error indicating how many tries were
// attempted. If overriding this, be sure to close the body if needed.
type ErrorHandler func(resp *http.Response, err error, numTries int) (*http.Response, error)

// WithContext returns wrapped Request with a shallow copy of underlying *http.Request
// with its context changed to ctx. The provided ctx must be non-nil.
func (r *Request) WithContext(ctx context.Context) *Request {
	r.Request = r.Request.WithContext(ctx)
	return r
}

// BodyBytes allows accessing the request body. It is an analogue to
// http.Request's Body variable, but it returns a copy of the underlying data
// rather than consuming it.
//
// This function is not thread-safe; do not call it at the same time as another
// call, or at the same time this request is being used with Client.Do.
func (r *Request) BodyBytes() ([]byte, error) {
	if r.Request.Body == nil {
		return nil, nil
	}
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(r.Body)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Update request URL with new changes of parameters if any
func (r *Request) Update() {
	r.URL.Update()
	updateScheme(r.URL.URL)
}

// SetURL updates request url (i.e http.Request.URL) with given url
func (r *Request) SetURL(u *urlutil.URL) {
	r.URL = u
	r.Request.URL = u.URL
	r.Update()
}

// Clones and returns new Request
func (r *Request) Clone(ctx context.Context) *Request {
	r.Update()
	ux := r.URL.Clone()
	req := r.Request.Clone(ctx)
	req.URL = ux.URL
	ux.Update()
	var auth *Auth
	if r.hasAuth() {
		auth = &Auth{
			Type:     r.Auth.Type,
			Username: r.Auth.Username,
			Password: r.Auth.Password,
		}
	}
	return &Request{
		Request: req,
		URL:     ux,
		Metrics: Metrics{}, // Metrics shouldn't be cloned
		Auth:    auth,
	}
}

// Dump returns request dump in bytes
func (r *Request) Dump() ([]byte, error) {
	resplen := int64(0)
	dumpbody := true
	clone := r.Clone(context.TODO())
	if clone.Body != nil {
		resplen, _ = getLength(clone.Body)
	}
	if resplen == 0 {
		dumpbody = false
		clone.ContentLength = 0
		clone.Body = nil
		delete(clone.Header, "Content-length")
	} else {
		clone.ContentLength = resplen
	}
	dumpBytes, err := httputil.DumpRequestOut(clone.Request, dumpbody)
	if err != nil {
		return nil, err
	}
	return dumpBytes, nil
}

// hasAuth checks if request has any username/password
func (request *Request) hasAuth() bool {
	return request.Auth != nil
}

// FromRequest wraps an http.Request in a retryablehttp.Request
func FromRequest(r *http.Request) (*Request, error) {
	req := Request{
		Request: r,
		Metrics: Metrics{},
		Auth:    nil,
	}

	if r.URL != nil {
		urlx, err := urlutil.Parse(r.URL.String())
		if err != nil {
			return nil, err
		}
		req.URL = urlx
	}

	if r.Body != nil {
		body, err := readerutil.NewReusableReadCloser(r.Body)
		if err != nil {
			return nil, err
		}
		r.Body = body
		req.ContentLength, err = getLength(body)
		if err != nil {
			return nil, err
		}
	}

	return &req, nil
}

// FromRequestWithTrace wraps an http.Request in a retryablehttp.Request with trace enabled
func FromRequestWithTrace(r *http.Request) (*Request, error) {
	trace := &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			fmt.Fprintf(os.Stderr, "Got connection\tReused: %v\tWas Idle: %v\tIdle Time: %v\n", connInfo.Reused, connInfo.WasIdle, connInfo.IdleTime)
		},
		ConnectStart: func(network, addr string) {
			fmt.Fprintf(os.Stderr, "Dial start\tnetwork: %s\taddress: %s\n", network, addr)
		},
		ConnectDone: func(network, addr string, err error) {
			fmt.Fprintf(os.Stderr, "Dial done\tnetwork: %s\taddress: %s\terr: %v\n", network, addr, err)
		},
		GotFirstResponseByte: func() {
			fmt.Fprintf(os.Stderr, "Got response's first byte\n")
		},
		WroteHeaders: func() {
			fmt.Fprintf(os.Stderr, "Wrote request headers\n")
		},
		WroteRequest: func(wr httptrace.WroteRequestInfo) {
			fmt.Fprintf(os.Stderr, "Wrote request, err: %v\n", wr.Err)
		},
	}

	r = r.WithContext(httptrace.WithClientTrace(r.Context(), trace))

	return FromRequest(r)
}

// NewRequest creates a new wrapped request.
func NewRequestFromURL(method string, urlx *urlutil.URL, body interface{}) (*Request, error) {
	return NewRequestFromURLWithContext(context.Background(), method, urlx, body)
}

// NewRequestWithContext creates a new wrapped request with context
func NewRequestFromURLWithContext(ctx context.Context, method string, urlx *urlutil.URL, body interface{}) (*Request, error) {
	bodyReader, contentLength, err := getReusableBodyandContentLength(body)
	if err != nil {
		return nil, err
	}

	// we provide a url without path to http.NewRequest at start and then replace url instance directly
	// because `http.NewRequest()` internally parses using `url.Parse()` this removes/overrides any
	// patches done by urlutil.URL in unsafe mode (ex: https://scanme.sh/%invalid)
	// Note: this does not have any impact on actual path when sending request
	// `http.NewRequestxxx` internally only uses `u.Host` and all other data is stored in `url.URL` instance
	httpReq, err := http.NewRequestWithContext(ctx, method, "https://"+urlx.Host, nil)
	if err != nil {
		return nil, err
	}
	urlx.Update()
	httpReq.URL = urlx.URL
	updateScheme(httpReq.URL)
	// content-length and body should be assigned only
	// if request has body
	if bodyReader != nil {
		httpReq.ContentLength = contentLength
		httpReq.Body = bodyReader
	}

	return &Request{httpReq, urlx, Metrics{}, nil}, nil
}

// NewRequest creates a new wrapped request
func NewRequest(method, url string, body interface{}) (*Request, error) {
	urlx, err := urlutil.Parse(url)
	if err != nil {
		return nil, err
	}
	return NewRequestFromURL(method, urlx, body)
}

// NewRequest creates a new wrapped request with given context
func NewRequestWithContext(ctx context.Context, method, url string, body interface{}) (*Request, error) {
	urlx, err := urlutil.Parse(url)
	if err != nil {
		return nil, err
	}
	return NewRequestFromURLWithContext(ctx, method, urlx, body)
}

func updateScheme(u *url.URL) {
	// when url without scheme is passed to url.URL it loosely parses and ususally actual host is either part of scheme or path
	// But this is sometimes handled internally when creating request using http.NewRequest
	// Also It is illegal to update http.Request.URL in serverHTTP https://github.com/golang/go/issues/18952 but no mention about client side

	// When Url of Request is updated (i.e http.Request.URL = tmp etc) this condition must be explicitly handled else
	// it causes `unsupported protocol scheme "" error `

	if u.Host != "" && u.Scheme == "" {
		if PreferHTTP {
			u.Scheme = "http"
		} else {
			u.Scheme = "https"
		}
	}
}
