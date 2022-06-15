package client

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http/httputil"
	"strconv"
	"strings"
)

// Version represents a HTTP version.
type Version struct {
	Major int
	Minor int
}

func (v *Version) String() string {
	return fmt.Sprintf("HTTP/%d.%d", v.Major, v.Minor)
}

var (
	HTTP_1_0 = Version{Major: 1, Minor: 0}
	HTTP_1_1 = Version{Major: 1, Minor: 1}
)

// Header represents a HTTP header.
type Header struct {
	Key   string
	Value string
}

// Request represents a complete HTTP request.
type Request struct {
	RawBytes               []byte
	AutomaticContentLength bool
	AutomaticHost          bool
	Method                 string
	Path                   string
	Query                  []string
	Version

	Headers []Header

	Body io.Reader
}

// ContentLength returns the length of the body. If the body length is not known
// ContentLength will return -1.
func (r *Request) ContentLength() int64 {
	// TODO(dfc) this should support anything with a Len() int64 method.
	if r.Body == nil {
		return -1
	}
	switch b := r.Body.(type) {
	case *bytes.Buffer:
		return int64(b.Len())
	case *strings.Reader:
		return int64(b.Len())
	default:
		return -1
	}
}

const readerBuffer = 4096

// Client represents a single connection to a http server. Client obeys KeepAlive conditions for
// HTTP but connection pooling is expected to be handled at a higher layer.
type Client interface {
	WriteRequest(*Request) error
	ReadResponse(forceReadAll bool) (*Response, error)
}

// NewClient returns a Client implementation which uses rw to communicate.
func NewClient(rw io.ReadWriter) Client {
	return &client{
		reader: reader{bufio.NewReaderSize(rw, readerBuffer)},
		writer: writer{Writer: rw},
	}
}

type client struct {
	reader
	writer
}

// SendRequest marshalls a HTTP request to the wire.
func (c *client) WriteRequest(req *Request) error {
	if len(req.RawBytes) > 0 {
		_, err := c.Write(req.RawBytes)
		return err
	}
	if err := c.WriteRequestLine(req.Method, req.Path, req.Query, req.Version.String()); err != nil {
		return err
	}
	for _, h := range req.Headers {
		if err := c.WriteHeader(h.Key, h.Value); err != nil {
			return err
		}
	}

	l := req.ContentLength()
	if req.AutomaticContentLength {
		if l >= 0 {
			if err := c.WriteHeader("Content-Length", fmt.Sprintf("%d", l)); err != nil {
				return err
			}
		}
	}

	if req.Body == nil {
		// doesn't actually start the body, just sends the terminating \r\n
		return c.StartBody()
	}

	if err := c.StartBody(); err != nil {
		return err
	}
	return c.WriteBody(req.Body)
}

// ReadResponse unmarshalls a HTTP response.
func (c *client) ReadResponse(forceReadAll bool) (*Response, error) {
	version, code, msg, err := c.ReadStatusLine()
	var headers []Header
	if err != nil {
		return nil, fmt.Errorf("ReadStatusLine: %v", err)
	}
	for {
		var key, value string
		var done bool
		key, value, done, err = c.ReadHeader()
		if err != nil || done {
			break
		}
		if key == "" {
			// empty header values are valid, rfc 2616 s4.2.
			err = errors.New("invalid header")
			break
		}
		headers = append(headers, Header{key, value})
	}
	var resp = Response{
		Version: version,
		Status:  Status{code, msg},
		Headers: headers,
		Body:    c.ReadBody(),
	}
	if l := resp.ContentLength(); l >= 0 && !forceReadAll {
		resp.Body = io.LimitReader(resp.Body, l)
	} else if resp.TransferEncoding() == "chunked" {
		resp.Body = httputil.NewChunkedReader(resp.Body)
	}
	return &resp, err
}

// Response represents an RFC2616 response.
type Response struct {
	Version
	Status
	Headers []Header
	Body    io.Reader
}

// ContentLength returns the length of the body. If the body length is not known
// ContentLength will return -1.
func (r *Response) ContentLength() int64 {
	for _, h := range r.Headers {
		if strings.EqualFold(h.Key, "Content-Length") {
			length, err := strconv.ParseInt(h.Value, 10, 64)
			if err != nil {
				continue
			}
			return int64(length)
		}
	}
	return -1
}

// CloseRequested returns if Reason includes a Connection: close header.
func (r *Response) CloseRequested() bool {
	for _, h := range r.Headers {
		if strings.EqualFold(h.Key, "Connection") {
			return h.Value == "close"
		}
	}
	return false
}

// TransferEncoding returns the transfer encoding this message was transmitted with.
// If not is specified by the sender, "identity" is assumed.
func (r *Response) TransferEncoding() string {
	for _, h := range r.Headers {
		if strings.EqualFold(h.Key, "Transfer-Encoding") {
			switch h.Value {
			case "identity", "chunked":
				return h.Value
			}
		}
	}
	return "identity"
}

// Message represents common traits of both Requests and Responses.
type Message interface {
	ContentLength() int64
	CloseRequested() bool
}
