package httputil

import (
	"net/http"
	"net/http/httputil"
)

// ChainItem request=>response
type ChainItem struct {
	Request    []byte
	Response   []byte
	StatusCode int
	Location   string
	RequestURL string
}

// GetChain if redirects
func GetChain(r *http.Response) (chain []ChainItem, err error) {
	lastresp := r
	for lastresp != nil {
		lastreq := lastresp.Request
		lastreqDump, err := httputil.DumpRequest(lastreq, false)
		if err != nil {
			return nil, err
		}
		lastrespDump, err := httputil.DumpResponse(lastresp, false)
		if err != nil {
			return nil, err
		}
		var location string
		if l, err := lastresp.Location(); err == nil {
			location = l.String()
		}
		requestURL := lastreq.URL.String()
		chain = append(chain, ChainItem{Request: lastreqDump, Response: lastrespDump, StatusCode: lastresp.StatusCode, Location: location, RequestURL: requestURL})
		// process next
		lastresp = lastreq.Response
	}
	// reverse the slice in order to have the chain in progressive order
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}

	return
}
