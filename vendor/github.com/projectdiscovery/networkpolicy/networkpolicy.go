package networkpolicy

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/gaissmai/bart"
	iputil "github.com/projectdiscovery/utils/ip"
	urlutil "github.com/projectdiscovery/utils/url"
)

func init() {
	DefaultOptions.DenyList = append(DefaultOptions.DenyList, DefaultIPv4DenylistRanges...)
	DefaultOptions.DenyList = append(DefaultOptions.DenyList, DefaultIPv6Denylist...)
	DefaultOptions.DenyList = append(DefaultOptions.DenyList, DefaultIPv6DenylistRanges...)
	DefaultOptions.DenyList = append(DefaultOptions.DenyList, DefaultIPv6Denylist...)
	DefaultOptions.AllowSchemeList = append(DefaultOptions.AllowSchemeList, DefaultSchemeAllowList...)
}

type Options struct {
	DenyList        []string
	AllowList       []string
	AllowSchemeList []string
	DenySchemeList  []string
	AllowPortList   []int
	DenyPortList    []int
}

// DefaultOptions is the base configuration for the validator
var DefaultOptions Options

type NetworkPolicy struct {
	Options    *Options
	hasFilters bool

	DenyRanger  *bart.Table[net.IP]
	AllowRanger *bart.Table[net.IP]

	AllowRules      map[string]*regexp.Regexp
	DenyRules       map[string]*regexp.Regexp
	AllowSchemeList map[string]struct{}
	DenySchemeList  map[string]struct{}
	AllowPortList   map[int]struct{}
	DenyPortList    map[int]struct{}
}

// New creates a new URL validator using the validator options
func New(options Options) (*NetworkPolicy, error) {
	allowSchemeList := make(map[string]struct{})
	for _, scheme := range options.AllowSchemeList {
		if !schemePattern.MatchString(scheme) {
			return nil, fmt.Errorf("invalid scheme format for allow list: %s", scheme)
		}
		allowSchemeList[scheme] = struct{}{}
	}

	denySchemeList := make(map[string]struct{})
	for _, scheme := range options.DenySchemeList {
		if !schemePattern.MatchString(scheme) {
			return nil, fmt.Errorf("invalid scheme format for deny list: %s", scheme)
		}
		denySchemeList[scheme] = struct{}{}
	}

	allowRules := make(map[string]*regexp.Regexp)
	denyRules := make(map[string]*regexp.Regexp)

	var allowRanger *bart.Table[net.IP]
	if len(options.AllowList) > 0 {
		allowRanger = new(bart.Table[net.IP])

		for _, r := range options.AllowList {
			// handle if ip/cidr
			cidr, err := asCidr(r)
			if err == nil {
				allowRanger.Insert(cidr, nil)
				continue
			}

			// handle as regex
			rgx, err := regexp.Compile(r)
			if err != nil {
				return nil, err
			}
			allowRules[r] = rgx
		}
	}

	var denyRanger *bart.Table[net.IP]
	if len(options.DenyList) > 0 {
		denyRanger = new(bart.Table[net.IP])

		for _, r := range options.DenyList {
			// handle if ip/cidr
			cidr, err := asCidr(r)
			if err == nil {
				denyRanger.Insert(cidr, nil)
				continue
			}

			// handle as regex
			rgx, err := regexp.Compile(r)
			if err != nil {
				return nil, err
			}
			denyRules[r] = rgx
		}
	}

	allowPortList := make(map[int]struct{})
	for _, p := range options.AllowPortList {
		allowPortList[p] = struct{}{}
	}

	denyPortList := make(map[int]struct{})
	for _, p := range options.DenyPortList {
		denyPortList[p] = struct{}{}
	}

	hasFilters := len(options.DenyList)+len(options.AllowList)+len(options.AllowSchemeList)+len(options.DenySchemeList)+len(options.AllowPortList)+len(options.DenyPortList) > 0

	return &NetworkPolicy{Options: &options, DenyRanger: denyRanger, AllowRanger: allowRanger, AllowSchemeList: allowSchemeList,
		DenySchemeList: denySchemeList, AllowRules: allowRules, DenyRules: denyRules, AllowPortList: allowPortList, DenyPortList: denyPortList, hasFilters: hasFilters}, nil
}

func (r NetworkPolicy) Validate(host string) bool {
	if !r.hasFilters {
		return true
	}

	// check if it's an ip
	if addr, ok := parseAddr(host); ok {
		return r.validateAddr(addr)
	}

	// names that resolvers and browsers read as an address (127.1, 2130706433, localhost) must not reach a denied range
	if r.hostAddrsDenied(host) {
		return false
	}

	// try to obtain scheme and port
	var hasPort bool
	var port int
	var hasScheme bool
	var scheme string

	// check if it's a valid URL
	var u *url.URL
	if URL, err := urlutil.Parse(host); err == nil {
		u = URL.URL
	} else if URL, err := url.Parse(host); err == nil {
		// urlutil rejects schemes it doesn't know (gopher, dict, file...), which would otherwise skip the scheme and port lists
		u = URL
	}
	// the host of a URL or host:port value; urlutil keeps some hosts (http://2130706433/) in the path
	if u != nil && r.hostAddrsDenied(u.Hostname()) {
		return false
	}
	if URL, err := url.Parse(host); err == nil && r.hostAddrsDenied(URL.Hostname()) {
		return false
	}
	if u != nil {
		// parse scheme
		scheme = u.Scheme
		hasScheme = scheme != ""
		// parse port
		var err error
		port, err = strconv.Atoi(u.Port())
		if err == nil {
			hasPort = true
		}
	}

	// check the port
	var isPortInDenyList, isPortInAllowedList bool

	if len(r.DenyPortList) > 0 && hasPort {
		_, isPortInDenyList = r.DenyPortList[port]
	}

	if len(r.AllowPortList) > 0 && hasPort {
		_, isPortInAllowedList = r.AllowPortList[port]
	} else {
		isPortInAllowedList = true
	}

	var isSchemeInDenyList, isSchemeInAllowedList bool
	if len(r.DenySchemeList) > 0 && hasScheme {
		_, isSchemeInDenyList = r.DenySchemeList[scheme]
	}

	if len(r.AllowSchemeList) > 0 && hasScheme {
		_, isSchemeInAllowedList = r.AllowSchemeList[scheme]
	} else {
		isSchemeInAllowedList = true
	}

	// regex
	var isInDenyList, isInAllowedList bool
	for _, r := range r.DenyRules {
		if r.MatchString(host) {
			isInDenyList = true
			break
		}
	}
	if len(r.AllowRules) > 0 {
		for _, r := range r.AllowRules {
			if r.MatchString(host) {
				isInAllowedList = true
				break
			}
		}
	} else {
		isInAllowedList = true
	}

	return !isSchemeInDenyList && !isInDenyList && isInAllowedList && isSchemeInAllowedList && !isPortInDenyList && isPortInAllowedList
}

func (r NetworkPolicy) ValidateURLWithIP(host string, ip string) bool {
	if !r.hasFilters {
		return true
	}
	return r.Validate(host) && r.ValidateAddress(ip)
}

func (r NetworkPolicy) ValidateAddress(IP string) bool {
	IPDest, ok := parseAddr(IP)
	if !ok {
		return false
	}
	return r.validateAddr(IPDest)
}

// validateAddr checks an address in its canonical form: zone removed and IPv4-mapped IPv6 (::ffff:a.b.c.d) unmapped,
// so IPv4 ranges also match the IPv6 forms that dial the same IPv4 host
func (r NetworkPolicy) validateAddr(addr netip.Addr) bool {
	if r.addrDenied(addr) {
		return false
	}

	if r.AllowRanger != nil && r.AllowRanger.Size() > 0 {
		addr = addr.WithZone("")
		return rangerContains(r.AllowRanger, addr.Unmap()) || rangerContains(r.AllowRanger, addr)
	}

	return true
}

// addrDenied checks the address as given and in its canonical form.
// The unspecified address (0.0.0.0, ::) dials the local host, so it is also checked as loopback.
func (r NetworkPolicy) addrDenied(addr netip.Addr) bool {
	if r.DenyRanger == nil || r.DenyRanger.Size() == 0 {
		return false
	}
	addr = addr.WithZone("")
	canonical := addr.Unmap()
	if rangerContains(r.DenyRanger, addr) || rangerContains(r.DenyRanger, canonical) {
		return true
	}
	if canonical.IsUnspecified() {
		for _, loopback := range loopbackAddrs {
			if rangerContains(r.DenyRanger, loopback) {
				return true
			}
		}
	}
	return false
}

// hostAddrsDenied reports whether host is an address form (IP literal, legacy IPv4 notation, localhost name)
// that dials an address in the deny list
func (r NetworkPolicy) hostAddrsDenied(host string) bool {
	if addr, ok := parseAddr(host); ok {
		return r.addrDenied(addr)
	}
	for _, addr := range hostAddrs(host) {
		if r.addrDenied(addr) {
			return true
		}
	}
	return false
}

func (r NetworkPolicy) ValidateAddressWithPort(IP string, port int) bool {
	return r.ValidateAddress(IP) && r.ValidatePort(port)
}

func (r NetworkPolicy) ValidatePort(port int) bool {
	if r.DenyPortList != nil && portIsListed(r.DenyPortList, port) {
		return false
	}

	if len(r.AllowPortList) > 0 {
		return portIsListed(r.AllowPortList, port)
	}

	return true
}

func asCidr(s string) (netip.Prefix, error) {
	if iputil.IsIP(s) {
		addr, err := netip.ParseAddr(s)
		if err == nil {
			if addr.Is4() {
				s += "/32"
			} else {
				s += "/128"
			}
		}
	}
	cidr, err := netip.ParsePrefix(s)
	if err != nil {
		return cidr, err
	}
	return cidr, nil
}

func rangerContains(ranger *bart.Table[net.IP], IP netip.Addr) bool {
	_, ok := ranger.Lookup(IP)
	return ok
}

func portIsListed(list map[int]struct{}, port int) bool {
	_, ok := list[port]
	return ok
}

// ValidateHost checks all the ips associated to a hostname and returns the valid ip if any
func (r NetworkPolicy) ValidateHost(host string) (string, bool) {
	if addr, ok := parseAddr(host); ok {
		if strings.HasPrefix(host, "[") {
			host = addr.String()
		}
		return host, r.Validate(host)
	}
	if r.hostAddrsDenied(host) {
		return "", false
	}
	// obtain ips from system resolvers
	addrs, err := net.LookupHost(host)
	if err != nil {
		// no addresses
		return "", false
	}

	for _, addr := range addrs {
		// if at least one address
		if r.Validate(addr) {
			return addr, true
		}
	}

	return "", false
}
