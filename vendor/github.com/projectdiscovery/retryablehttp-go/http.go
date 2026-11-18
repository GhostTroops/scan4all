package retryablehttp

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"golang.org/x/net/http2"
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
	fd, _ := getFastDialer()
	transport := &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		MaxIdleConns:           100,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    10 * time.Second,
		ExpectContinueTimeout:  1 * time.Second,
		MaxIdleConnsPerHost:    100,
		MaxResponseHeaderBytes: 4096, // net/http default is 10Mb
		TLSClientConfig: &tls.Config{
			ClientSessionCache: tls.NewLRUClientSessionCache(1024),
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

// newHTTP2Client returns a copy of client for the fallback in [Client.Do]. The
// copy keeps the proxy, dialer, TLS config, cookie jar, redirect policy and
// timeout of client, and attempts HTTP/2 on its own clone of the transport.
//
// A transport other than [*http.Transport] cannot be cloned, so the copy
// shares it as is rather than bypassing it.
func newHTTP2Client(client *http.Client) (*http.Client, error) {
	c := *client

	rt := client.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	transport, ok := rt.(*http.Transport)
	if !ok {
		return &c, nil
	}

	transport = transport.Clone()
	// Without this, a custom TLS config or dialer disables HTTP/2, and
	// http2.ConfigureTransport is a no-op since Go 1.27.
	transport.ForceAttemptHTTP2 = true
	// ConfigureTransport stays despite its deprecation: on Go 1.26, the go.mod
	// minimum, it routes HTTP/2 through golang.org/x/net/http2, and setting
	// [http.Transport.Protocols] instead would switch to the copy bundled with
	// net/http.
	if err := http2.ConfigureTransport(transport); err != nil { //nolint:staticcheck // SA1019: see above.
		return nil, err
	}
	c.Transport = transport

	return &c, nil
}

// applyTLSSessionCache configures the TLS session cache size for an
// [http.Client].
//
// It only applies if the client has an [http.Transport] with a
// TLSClientConfig.
func applyTLSSessionCache(client *http.Client, size int) {
	if transport, ok := client.Transport.(*http.Transport); ok {
		if transport.TLSClientConfig != nil {
			transport.TLSClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(size)
		}
	}
}

var (
	fdInit = &sync.Once{}
	fd     *fastdialer.Dialer
	err    error
)

// getFastDialer returns a fastdialer.Dialer instance without creating it again
func getFastDialer() (*fastdialer.Dialer, error) {
	fdInit.Do(func() {
		opts := fastdialer.DefaultOptions
		// Keep the DNS cache in memory whatever the fastdialer default is.
		opts.CacheType = fastdialer.Memory
		fd, err = fastdialer.NewDialer(opts)
	})
	return fd, err
}

func init() {
	value := os.Getenv("DISABLE_ZTLS_FALLBACK")
	if strings.EqualFold(value, "true") {
		DisableZTLSFallback = true
	}
}
