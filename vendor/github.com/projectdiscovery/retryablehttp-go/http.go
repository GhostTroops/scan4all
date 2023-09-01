package retryablehttp

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
)

// DisableZTLSFallback disables use of ztls when there is error in tls handshake
// can also be disabled by setting DISABLE_ZTLS_FALLBACK env variable to true
var DisableZTLSFallback = false

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
	opts := fastdialer.DefaultOptions
	opts.CacheType = fastdialer.Memory
	fd, _ := fastdialer.NewDialer(opts)
	transport := &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		MaxIdleConns:           100,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    10 * time.Second,
		ExpectContinueTimeout:  1 * time.Second,
		MaxIdleConnsPerHost:    100,
		MaxResponseHeaderBytes: 4096, // net/http default is 10Mb
		TLSClientConfig: &tls.Config{
			Renegotiation:      tls.RenegotiateOnceAsClient, // Renegotiation is not supported in TLS 1.3 as per docs
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
	}
	if fd != nil {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return fd.Dial(ctx, network, addr)
		}
		transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return fd.DialTLS(ctx, network, addr)
		}
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

func init() {
	value := os.Getenv("DISABLE_ZTLS_FALLBACK")
	if strings.EqualFold(value, "true") {
		DisableZTLSFallback = true
	}
}
