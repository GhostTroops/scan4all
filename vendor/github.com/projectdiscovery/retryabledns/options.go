package retryabledns

import (
	"errors"
	"fmt"
	"net"
	"time"
)

var (
	ErrMaxRetriesZero = errors.New("retries must be at least 1")
	ErrResolversEmpty = errors.New("resolvers list must not be empty")
)

type Options struct {
	BaseResolvers         []string
	MaxRetries            int
	Timeout               time.Duration
	Hostsfile             bool
	LocalAddrIP           net.IP
	LocalAddrPort         uint16
	ConnectionPoolThreads int
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
	return nil
}
