package httputil

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
)

// AllHTTPMethods contains all available HTTP methods
func AllHTTPMethods() []string {
	return []string{
		http.MethodGet,
		http.MethodHead,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodConnect,
		http.MethodOptions,
		http.MethodTrace,
	}
}

// DumpRequest to string
func DumpRequest(req *http.Request) (string, error) {
	dump, err := httputil.DumpRequestOut(req, true)

	return string(dump), err
}

// DumpResponseHeadersAndRaw returns http headers and response as strings
func DumpResponseHeadersAndRaw(resp *http.Response) (headers, fullresp []byte, err error) {
	// httputil.DumpResponse does not work with websockets
	if resp.StatusCode >= http.StatusContinue && resp.StatusCode <= http.StatusEarlyHints {
		raw := resp.Status + "\n"
		for h, v := range resp.Header {
			raw += fmt.Sprintf("%s: %s\n", h, v)
		}
		return []byte(raw), []byte(raw), nil
	}
	headers, err = httputil.DumpResponse(resp, false)
	if err != nil {
		return
	}
	fullresp, err = httputil.DumpResponse(resp, true)
	return
}

// DrainResponseBody drains and closes the response body
func DrainResponseBody(resp *http.Response) {
	if resp.Body != http.NoBody && resp.Body != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}
