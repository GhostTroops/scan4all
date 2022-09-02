package protocolstate

import (
	"fmt"
	"net"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Dialer is a shared fastdialer instance for host DNS resolution
var Dialer *fastdialer.Dialer

// Init creates the Dialer instance based on user configuration
func Init(options *types.Options) error {
	if Dialer != nil {
		return nil
	}
	opts := fastdialer.DefaultOptions

	switch {
	case options.SourceIP != "" && options.Interface != "":
		isAssociated, err := isIpAssociatedWithInterface(options.SourceIP, options.Interface)
		if err != nil {
			return err
		}
		if isAssociated {
			opts.Dialer = &net.Dialer{
				LocalAddr: &net.TCPAddr{
					IP: net.ParseIP(options.SourceIP),
				},
			}
		} else {
			return fmt.Errorf("source ip (%s) is not associated with the interface (%s)", options.SourceIP, options.Interface)
		}
	case options.SourceIP != "":
		isAssociated, err := isIpAssociatedWithInterface(options.SourceIP, "any")
		if err != nil {
			return err
		}
		if isAssociated {
			opts.Dialer = &net.Dialer{
				LocalAddr: &net.TCPAddr{
					IP: net.ParseIP(options.SourceIP),
				},
			}
		} else {
			return fmt.Errorf("source ip (%s) is not associated with any network interface", options.SourceIP)
		}
	case options.Interface != "":
		ifadrr, err := interfaceAddress(options.Interface)
		if err != nil {
			return err
		}
		opts.Dialer = &net.Dialer{
			LocalAddr: &net.TCPAddr{
				IP: ifadrr,
			},
		}
	}

	if options.SystemResolvers {
		opts.EnableFallback = true
	}
	if options.ResolversFile != "" {
		opts.BaseResolvers = options.InternalResolversList
	}
	opts.WithDialerHistory = true
	opts.WithZTLS = options.ZTLS
	opts.SNIName = options.SNI
	dialer, err := fastdialer.NewDialer(opts)
	if err != nil {
		return errors.Wrap(err, "could not create dialer")
	}
	Dialer = dialer
	return nil
}

// isIpAssociatedWithInterface checks if the given IP is associated with the given interface.
func isIpAssociatedWithInterface(souceIP, interfaceName string) (bool, error) {
	addrs, err := interfaceAddresses(interfaceName)
	if err != nil {
		return false, err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.String() == souceIP {
				return true, nil
			}
		}
	}
	return false, nil
}

// interfaceAddress returns the first IPv4 address of the given interface.
func interfaceAddress(interfaceName string) (net.IP, error) {
	addrs, err := interfaceAddresses(interfaceName)
	if err != nil {
		return nil, err
	}
	var address net.IP
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				address = ipnet.IP
			}
		}
	}
	if address == nil {
		return nil, fmt.Errorf("no suitable address found for interface: `%s`", interfaceName)
	}
	return address, nil
}

// interfaceAddresses returns all interface addresses.
func interfaceAddresses(interfaceName string) ([]net.Addr, error) {
	if interfaceName == "any" {
		return net.InterfaceAddrs()
	}
	ief, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get interface: `%s`", interfaceName)
	}
	addrs, err := ief.Addrs()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get interface addresses for: `%s`", interfaceName)
	}
	return addrs, nil
}

// Close closes the global shared fastdialer
func Close() {
	if Dialer != nil {
		Dialer.Close()
	}
}
