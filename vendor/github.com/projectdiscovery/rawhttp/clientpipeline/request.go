package clientpipeline

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/projectdiscovery/rawhttp/client"
)

var (
	HTTP_1_0 = Version{Major: 1, Minor: 0}
	HTTP_1_1 = Version{Major: 1, Minor: 1}
)

type Version struct {
	Major int
	Minor int
}

func (v *Version) String() string {
	return fmt.Sprintf("HTTP/%d.%d", v.Major, v.Minor)
}

// Header represents a HTTP header.
type Header struct {
	Key   string
	Value string
}

// Request represents a complete HTTP request.
type Request struct {
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

func (r *Request) Write(w *bufio.Writer) error {
	q := strings.Join(r.Query, "&")
	if len(q) > 0 {
		q = "?" + q
	}
	if _, err := fmt.Fprintf(w, "%s %s%s %s\r\n", r.Method, r.Path, q, r.Version.String()); err != nil {
		return err
	}

	for _, h := range r.Headers {
		var err error
		if h.Value != "" {
			_, err = fmt.Fprintf(w, "%s: %s\r\n", h.Key, h.Value)
		} else {
			_, err = fmt.Fprintf(w, "%s\r\n", h.Key)
		}
		if err != nil {
			return err
		}
	}

	l := r.ContentLength()
	if r.AutomaticContentLength {
		if l >= 0 {
			if _, err := fmt.Fprintf(w, "Content-Length: %d", l); err != nil {
				return err
			}
		}
	}

	if r.Body == nil {
		// doesn't actually start the body, just sends the terminating \r\n
		_, err := fmt.Fprintf(w, client.NewLine)
		return err
	}

	// TODO(dfc) Version should implement comparable so we can say version >= HTTP_1_1
	// if r.Version.Major == 1 && r.Version.Minor == 1 {
	// 	if l < 0 {
	// 		if _, err := fmt.Fprintf(w, "Transfer-Encoding: chunked\r\n"); err != nil {
	// 			return err
	// 		}
	// 		if _, err := fmt.Fprintf(w, client.NewLine); err != nil {
	// 			return err
	// 		}
	// 		cw := httputil.NewChunkedWriter(w)
	// 		_, err := io.Copy(cw, r.Body)
	// 		return err
	// 	}
	// }
	if _, err := fmt.Fprintf(w, client.NewLine); err != nil {
		return err
	}
	_, err := io.Copy(w, r.Body)
	return err
}

func ToRequest(method string, path string, query []string, headers map[string][]string, body io.Reader) *Request {
	return &Request{
		Method:  method,
		Path:    path,
		Query:   query,
		Version: HTTP_1_1,
		Headers: toHeaders(headers),
		Body:    body,
	}
}

func toHeaders(h map[string][]string) []Header {
	var r []Header
	for k, v := range h {
		for _, v := range v {
			r = append(r, Header{Key: k, Value: v})
		}
	}
	return r
}
