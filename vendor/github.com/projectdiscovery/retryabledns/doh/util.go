package doh

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"time"
)

// ClientOption defines a function type for configuring an http.Client
type ClientOption func(*http.Client)

// WithTimeout sets the timeout for the http.Client
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *http.Client) {
		c.Timeout = timeout
	}
}

// WithInsecureSkipVerify sets the InsecureSkipVerify option for the TLS config
func WithInsecureSkipVerify() ClientOption {
	return func(c *http.Client) {
		transport, ok := c.Transport.(*http.Transport)
		if !ok {
			transport = &http.Transport{}
			c.Transport = transport
		}
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}
		transport.TLSClientConfig.InsecureSkipVerify = true
	}
}

// WithProxy sets a proxy for the http.Client
func WithProxy(proxyURL string) ClientOption {
	return func(c *http.Client) {
		if proxyURL == "" {
			return
		}
		proxyURL, err := url.Parse(proxyURL)
		if err != nil {
			return
		}

		transport, ok := c.Transport.(*http.Transport)
		if !ok {
			transport = &http.Transport{}
			c.Transport = transport
		}

		transport.Proxy = http.ProxyURL(proxyURL)
	}
}

// NewHttpClient creates a new http.Client with the given options
func NewHttpClient(opts ...ClientOption) *http.Client {
	client := &http.Client{}
	for _, opt := range opts {
		opt(client)
	}
	return client
}
