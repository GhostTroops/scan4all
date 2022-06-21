package retryablehttp

import (
	"io"
	"io/ioutil"
	"net/http"
)

type ContextOverride string

const (
	RETRY_MAX ContextOverride = "retry-max"
)

// Discard is an helper function that discards the response body and closes the underlying connection
func Discard(req *Request, resp *http.Response, RespReadLimit int64) {
	_, err := io.Copy(ioutil.Discard, io.LimitReader(resp.Body, RespReadLimit))
	if err != nil {
		req.Metrics.DrainErrors++
	}
	resp.Body.Close()
}
