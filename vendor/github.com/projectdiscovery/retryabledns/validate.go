package retryabledns

import "net"

// ipv4InternalRanges contains the IP ranges internal in IPv4 range.
var ipv4InternalRanges = []string{
	"0.0.0.0/8",       // Current network (only valid as source address)
	"10.0.0.0/8",      // Private network
	"100.64.0.0/10",   // Shared Address Space
	"127.0.0.0/8",     // Loopback
	"169.254.0.0/16",  // Link-local (Also many cloud providers Metadata endpoint)
	"172.16.0.0/12",   // Private network
	"192.0.0.0/24",    // IETF Protocol Assignments
	"192.0.2.0/24",    // TEST-NET-1, documentation and examples
	"192.88.99.0/24",  // IPv6 to IPv4 relay (includes 2002::/16)
	"192.168.0.0/16",  // Private network
	"198.18.0.0/15",   // Network benchmark tests
	"198.51.100.0/24", // TEST-NET-2, documentation and examples
	"203.0.113.0/24",  // TEST-NET-3, documentation and examples
	"224.0.0.0/4",     // IP multicast (former Class D network)
	"240.0.0.0/4",     // Reserved (former Class E network)
}

// ipv6InternalRanges contains the IP ranges internal in IPv6 range.
var ipv6InternalRanges = []string{
	"::1/128",       // Loopback
	"64:ff9b::/96",  // IPv4/IPv6 translation (RFC 6052)
	"100::/64",      // Discard prefix (RFC 6666)
	"2001::/32",     // Teredo tunneling
	"2001:10::/28",  // Deprecated (previously ORCHID)
	"2001:20::/28",  // ORCHIDv2
	"2001:db8::/32", // Addresses used in documentation and example source code
	"2002::/16",     // 6to4
	"fc00::/7",      // Unique local address
	"fe80::/10",     // Link-local address
	"ff00::/8",      // Multicast
}

// internalRangeChecker contains a list of internal IP ranges.
type internalRangeChecker struct {
	ipv4 []*net.IPNet
	ipv6 []*net.IPNet
}

// newInternalRangeChecker creates a structure for checking if a host is from
// a internal IP range whether its ipv4 or ipv6.
func newInternalRangeChecker() (*internalRangeChecker, error) {
	rangeChecker := internalRangeChecker{}

	err := rangeChecker.appendIPv4Ranges(ipv4InternalRanges)
	if err != nil {
		return nil, err
	}

	err = rangeChecker.appendIPv6Ranges(ipv6InternalRanges)
	if err != nil {
		return nil, err
	}
	return &rangeChecker, nil
}

// appendIPv4Ranges adds a list of IPv4 Ranges to the list.
func (r *internalRangeChecker) appendIPv4Ranges(ranges []string) error {
	for _, ip := range ranges {
		_, rangeNet, err := net.ParseCIDR(ip)
		if err != nil {
			return err
		}
		r.ipv4 = append(r.ipv4, rangeNet)
	}
	return nil
}

// appendIPv6Ranges adds a list of IPv6 Ranges to the list.
func (r *internalRangeChecker) appendIPv6Ranges(ranges []string) error {
	for _, ip := range ranges {
		_, rangeNet, err := net.ParseCIDR(ip)
		if err != nil {
			return err
		}
		r.ipv6 = append(r.ipv6, rangeNet)
	}
	return nil
}

// ContainsIPv4 checks whether a given IP address exists in the internal IPv4 ranges.
func (r *internalRangeChecker) ContainsIPv4(IP net.IP) bool {
	for _, net := range r.ipv4 {
		if net.Contains(IP) {
			return true
		}
	}
	return false
}

// ContainsIPv6 checks whether a given IP address exists in the internal IPv6 ranges.
func (r *internalRangeChecker) ContainsIPv6(IP net.IP) bool {
	for _, net := range r.ipv6 {
		if net.Contains(IP) {
			return true
		}
	}
	return false
}
