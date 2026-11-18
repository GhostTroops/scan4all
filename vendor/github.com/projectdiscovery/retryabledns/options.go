package retryabledns

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"
)

var (
	ErrMaxRetriesZero = errors.New("retries must be at least 1")
	ErrResolversEmpty = errors.New("resolvers list must not be empty")

	ErrProxySchemeUnsupported = errors.New("proxy scheme must be socks5 or socks5h")

	BaseResolvers = []string{
		"1.1.1.1:53",
		"1.0.0.1:53",
		"8.8.8.8:53",
		"8.8.4.4:53",
	}
	DefaultOptions = Options{
		BaseResolvers: BaseResolvers,
		MaxRetries:    1,
		Timeout:       3 * time.Second,
	}
)

type Options struct {
	BaseResolvers         []string
	MaxRetries            int
	Timeout               time.Duration
	Hostsfile             bool
	LocalAddrIP           net.IP
	LocalAddrPort         uint16
	ConnectionPoolThreads int
	MaxPerCNAMEFollows    int

	// Proxy is the URL of a SOCKS5 proxy that queries go through, for
	// example "socks5://user:password@127.0.0.1:1080". The credentials
	// are optional. Only the socks5 and socks5h schemes are accepted;
	// any other scheme, including http and https, makes Validate fail
	// with ErrProxySchemeUnsupported. When set, UDP resolvers are
	// queried over TCP. An empty value disables the proxy.
	Proxy string

	// ExitOnStatusCodes lists DNS rcodes that terminate the retry
	// loop. When non-empty, only attempts whose rcode is in this list
	// are considered definitive: the response is parsed into the
	// returned DNSData and the loop exits. Attempts with any other
	// rcode are treated like transport errors - the response is not
	// parsed, DNSData is not mutated, and the loop continues with the
	// next resolver.
	//
	// Common values:
	//
	//	[]int{dns.RcodeSuccess}                       // NOERROR only
	//	[]int{dns.RcodeSuccess, dns.RcodeNameError}   // NOERROR or NXDOMAIN
	//
	// An empty/nil list preserves the legacy behavior: every attempt
	// is parsed, DNSData.Raw accumulates across retries, and only
	// RcodeSuccess breaks the loop.
	ExitOnStatusCodes []int
}

// exitOnRcode reports whether rcode is one of the configured
// terminating status codes. It returns true when no list is set so the
// historical "break on success" path keeps working unchanged at the
// call sites that gate on it.
func (options *Options) exitOnRcode(rcode int) bool {
	if len(options.ExitOnStatusCodes) == 0 {
		return rcode == 0 // dns.RcodeSuccess
	}
	for _, c := range options.ExitOnStatusCodes {
		if c == rcode {
			return true
		}
	}
	return false
}

// Returns a net.Addr of a UDP or TCP type depending on whats required
func (options *Options) GetLocalAddr(proto Protocol) net.Addr {
	if options.LocalAddrIP == nil {
		return nil
	}
	ipPort := net.JoinHostPort(options.LocalAddrIP.String(), fmt.Sprint(options.LocalAddrPort))
	var ipAddr net.Addr
	switch proto {
	case UDP:
		ipAddr, _ = net.ResolveUDPAddr("udp", ipPort)
	default:
		ipAddr, _ = net.ResolveTCPAddr("tcp", ipPort)
	}
	return ipAddr
}

// Sets the ip from a string, if invalid sets as nil
func (options *Options) SetLocalAddrIP(ip string) {
	// invalid ips are no-ops
	options.LocalAddrIP = net.ParseIP(ip)
}

// Sets the first available IP from a network interface name e.g. eth0
func (options *Options) SetLocalAddrIPFromNetInterface(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return err
	}
	for _, addr := range addrs {
		ipnetAddr, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		options.LocalAddrIP = ipnetAddr.IP
		return nil
	}
	return errors.New("no ip address found for interface")
}

func (options *Options) Validate() error {
	if options.MaxRetries == 0 {
		return ErrMaxRetriesZero
	}

	if len(options.BaseResolvers) == 0 {
		return ErrResolversEmpty
	}

	return options.validateProxy()
}

// validateProxy checks that Proxy, when set, is a SOCKS5 proxy URL.
func (options *Options) validateProxy() error {
	if options.Proxy == "" {
		return nil
	}
	proxyURL, err := url.Parse(options.Proxy)
	if err != nil {
		// drop the raw URL that url.Error carries, it may hold credentials
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return fmt.Errorf("invalid proxy URL: %w", err)
	}
	switch proxyURL.Scheme {
	case "socks5", "socks5h":
		return nil
	}
	return fmt.Errorf("%w: got %q", ErrProxySchemeUnsupported, proxyURL.Scheme)
}
