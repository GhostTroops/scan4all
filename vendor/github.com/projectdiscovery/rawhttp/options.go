package rawhttp

import (
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/rawhttp/client"
)

// Options contains configuration options for rawhttp client
type Options struct {
	Timeout         time.Duration
	FollowRedirects bool
	// FollowHostRedirects follows a redirect only when the next request
	// connects to the same host and port as the current one, over the same
	// protocol (HTTP or HTTPS). The host must match exactly, letter case
	// included. Otherwise the redirect response is returned. It follows such
	// redirects even when FollowRedirects is false.
	FollowHostRedirects    bool
	MaxRedirects           int
	AutomaticHostHeader    bool
	AutomaticContentLength bool
	CustomHeaders          client.Headers
	ForceReadAllBody       bool // ignores content length and reads all body
	CustomRawBytes         []byte
	Proxy                  string
	ProxyDialTimeout       time.Duration
	SNI                    string
	FastDialer             *fastdialer.Dialer
}

// DefaultOptions is the default configuration options for the client
var DefaultOptions = &Options{
	Timeout:                30 * time.Second,
	FollowRedirects:        true,
	MaxRedirects:           10,
	AutomaticHostHeader:    true,
	AutomaticContentLength: true,
}
