package rawhttp

import (
	"io"
	"net/http"

	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
)

// DefaultClient is the default HTTP client for doing raw requests
var DefaultClient = Client{
	dialer:  new(dialer),
	Options: DefaultOptions,
}

// Get makes a GET request to a given URL
func Get(url string) (*http.Response, error) {
	return DefaultClient.Get(url)
}

// Post makes a POST request to a given URL
func Post(url string, mimetype string, r io.Reader) (*http.Response, error) {
	return DefaultClient.Post(url, mimetype, r)
}

// Do sends a http request and returns a response
func Do(req *http.Request) (*http.Response, error) {
	return DefaultClient.Do(req)
}

// Dor sends a retryablehttp request and returns a response
func Dor(req *retryablehttp.Request) (*http.Response, error) {
	return DefaultClient.Dor(req)
}

// DoRaw does a raw request with some configuration
func DoRaw(method, url, uripath string, headers map[string][]string, body io.Reader) (*http.Response, error) {
	return DefaultClient.DoRaw(method, url, uripath, headers, body)
}

// DoRawWithOptions does a raw request with some configuration
func DoRawWithOptions(method, url, uripath string, headers map[string][]string, body io.Reader, options *Options) (*http.Response, error) {
	return DefaultClient.DoRawWithOptions(method, url, uripath, headers, body, options)
}
