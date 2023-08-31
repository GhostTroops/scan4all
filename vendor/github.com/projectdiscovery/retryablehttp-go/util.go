package retryablehttp

import (
	"io"
	"net/http"

	readerutil "github.com/projectdiscovery/utils/reader"
)

type ContextOverride string

const (
	RETRY_MAX ContextOverride = "retry-max"
)

// Discard is an helper function that discards the response body and closes the underlying connection
func Discard(req *Request, resp *http.Response, RespReadLimit int64) {
	_, err := io.Copy(io.Discard, io.LimitReader(resp.Body, RespReadLimit))
	if err != nil {
		req.Metrics.DrainErrors++
	}
	resp.Body.Close()
}

// getLength returns length of a Reader efficiently
func getLength(x io.Reader) (int64, error) {
	len, err := io.Copy(io.Discard, x)
	return len, err
}

func getReusableBodyandContentLength(rawBody interface{}) (*readerutil.ReusableReadCloser, int64, error) {

	var bodyReader *readerutil.ReusableReadCloser
	var contentLength int64

	if rawBody != nil {
		switch body := rawBody.(type) {
		// If they gave us a function already, great! Use it.
		case readerutil.ReusableReadCloser:
			bodyReader = &body
		case *readerutil.ReusableReadCloser:
			bodyReader = body
		// If they gave us a reader function read it and get reusablereader
		case func() (io.Reader, error):
			tmp, err := body()
			if err != nil {
				return nil, 0, err
			}
			bodyReader, err = readerutil.NewReusableReadCloser(tmp)
			if err != nil {
				return nil, 0, err
			}
		// If ReusableReadCloser is not given try to create new from it
		// if not possible return error
		default:
			var err error
			bodyReader, err = readerutil.NewReusableReadCloser(body)
			if err != nil {
				return nil, 0, err
			}
		}
	}

	if bodyReader != nil {
		var err error
		contentLength, err = getLength(bodyReader)
		if err != nil {
			return nil, 0, err
		}
	}

	return bodyReader, contentLength, nil
}
