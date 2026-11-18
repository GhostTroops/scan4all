package networkpolicy

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

var DefaultIPv4Denylist = []string{
	"255.255.255.255", // Broadcast
}
var DefaultIPv6Denylist = []string{}

var loopbackAddrs = []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()}

// parseAddr parses an IP literal, also in brackets ([::1]) or with a zone (fe80::1%lo0)
func parseAddr(host string) (netip.Addr, bool) {
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

// hostAddrs returns the addresses that system resolvers and browsers give for a name that is not an IP literal:
// loopback for localhost names, and the legacy IPv4 forms of inet_aton (127.1, 2130706433, 0x7f.0.0.1, 0177.0.0.1).
// A part with a leading zero is octal for glibc and browsers but decimal for the macOS resolver, so both are returned.
func hostAddrs(host string) []netip.Addr {
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	if name == "localhost" || strings.HasSuffix(name, ".localhost") {
		return loopbackAddrs
	}

	var addrs []netip.Addr
	for _, octal := range []bool{true, false} {
		if addr, ok := parseLegacyIPv4(name, octal); ok && !slices.Contains(addrs, addr) {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

// parseLegacyIPv4 parses one to four numeric parts; the last part fills the remaining bytes
func parseLegacyIPv4(name string, octal bool) (netip.Addr, bool) {
	parts := strings.Split(name, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false
	}
	var value uint64
	for i, part := range parts {
		base := 10
		switch {
		case len(part) > 2 && (part[:2] == "0x"):
			base, part = 16, part[2:]
		case len(part) > 1 && part[0] == '0' && octal:
			base, part = 8, part[1:]
		}
		n, err := strconv.ParseUint(part, base, 32)
		if err != nil {
			return netip.Addr{}, false
		}
		if i < len(parts)-1 {
			if n > 0xff {
				return netip.Addr{}, false
			}
			value = value<<8 | n
			continue
		}
		bits := 8 * (5 - len(parts))
		if n >= 1<<bits {
			return netip.Addr{}, false
		}
		value = value<<bits | n
	}
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}), true
}
