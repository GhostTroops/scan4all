package retryablehttp

import (
	"net/http"
	"net/url"
)

// DefaultHTTPClient is the http client with DefaultOptionsSingle options.
var DefaultHTTPClient *Client

func init() {
	DefaultHTTPClient = NewClient(DefaultOptionsSingle)
}

// Get issues a GET to the specified URL.
func Get(url string) (*http.Response, error) {
	return DefaultHTTPClient.Get(url)
}

// Head issues a HEAD to the specified URL.
func Head(url string) (*http.Response, error) {
	return DefaultHTTPClient.Head(url)
}

// Post issues a POST to the specified URL.
func Post(url, bodyType string, body interface{}) (*http.Response, error) {
	return DefaultHTTPClient.Post(url, bodyType, body)
}

// PostForm issues a POST to the specified URL, with data's keys and values
func PostForm(url string, data url.Values) (*http.Response, error) {
	return DefaultHTTPClient.PostForm(url, data)
}
