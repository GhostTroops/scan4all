package retryablehttp

import (
	"net/http"
	"net/url"
	"strings"
)

// Get is a convenience helper for doing simple GET requests.
func (c *Client) Get(url string) (*http.Response, error) {
	req, err := NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Head is a convenience method for doing simple HEAD requests.
func (c *Client) Head(url string) (*http.Response, error) {
	req, err := NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Post is a convenience method for doing simple POST requests.
func (c *Client) Post(url, bodyType string, body interface{}) (*http.Response, error) {
	req, err := NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", bodyType)
	return c.Do(req)
}

// PostForm is a convenience method for doing simple POST operations using
// pre-filled url.Values form data.
func (c *Client) PostForm(url string, data url.Values) (*http.Response, error) {
	return c.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}
