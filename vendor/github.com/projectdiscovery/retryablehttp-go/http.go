package retryablehttp

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// DefaultHostSprayingTransport returns a new http.Transport with similar default values to
// http.DefaultTransport, but with idle connections and keepalives disabled.
func DefaultHostSprayingTransport() *http.Transport {
	transport := DefaultReusePooledTransport()
	transport.DisableKeepAlives = true
	transport.MaxIdleConnsPerHost = -1
	return transport
}

// DefaultReusePooledTransport returns a new http.Transport with similar default
// values to http.DefaultTransport. Do not use this for transient transports as
// it can leak file descriptors over time. Only use this for transports that
// will be re-used for the same host(s).
func DefaultReusePooledTransport() *http.Transport {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:           100,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    10 * time.Second,
		ExpectContinueTimeout:  1 * time.Second,
		MaxIdleConnsPerHost:    100,
		MaxResponseHeaderBytes: 4096, // net/http default is 10Mb
		TLSClientConfig: &tls.Config{
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
	}
	return transport
}

// DefaultClient returns a new http.Client with similar default values to
// http.Client, but with a non-shared Transport, idle connections disabled, and
// keepalives disabled.
func DefaultClient() *http.Client {
	return &http.Client{
		Transport: DefaultHostSprayingTransport(),
	}
}

// DefaultPooledClient returns a new http.Client with similar default values to
// http.Client, but with a shared Transport. Do not use this function for
// transient clients as it can leak file descriptors over time. Only use this
// for clients that will be re-used for the same host(s).
func DefaultPooledClient() *http.Client {
	return &http.Client{
		Transport: DefaultReusePooledTransport(),
	}
}
