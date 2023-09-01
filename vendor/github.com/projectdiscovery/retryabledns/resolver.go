package retryabledns

import (
	"net"
	"strings"

	stringsutil "github.com/projectdiscovery/utils/strings"
)

type Protocol string

const (
	UDP Protocol = "udp"
	TCP Protocol = "tcp"
	DOH Protocol = "doh"
	DOT Protocol = "dot"
)

func (p Protocol) String() string {
	return string(p)
}

func (p Protocol) StringWithSemicolon() string {
	return p.String() + ":"
}

type DohProtocol string

const (
	JsonAPI DohProtocol = "jsonapi"
	GET     DohProtocol = "get"
	POST    DohProtocol = "post"
)

func (p DohProtocol) String() string {
	return string(p)
}

func (p DohProtocol) StringWithSemicolon() string {
	return ":" + p.String()
}

type Resolver interface {
	String() string
}

type NetworkResolver struct {
	Protocol Protocol
	Host     string
	Port     string
}

func (r NetworkResolver) String() string {
	return net.JoinHostPort(r.Host, r.Port)
}

type DohResolver struct {
	Protocol DohProtocol
	URL      string
}

func (r DohResolver) Method() string {
	if r.Protocol == POST {
		return POST.String()
	}

	return GET.String()
}

func (r DohResolver) String() string {
	return r.URL
}

func parseResolver(r string) (resolver Resolver) {
	rNetworkTokens := trimProtocol(r)
	protocol := UDP

	if len(r) >= 4 && r[3] == 58 { // 58 is ":"
		switch r[0:3] {
		case "udp":
		case "tcp":
			protocol = TCP
		case "dot":
			protocol = DOT
		case "doh":
			protocol = DOH
			isJsonApi, isGet := hasDohProtocol(r, JsonAPI.StringWithSemicolon()), hasDohProtocol(r, GET.StringWithSemicolon())
			URL := trimDohProtocol(rNetworkTokens)
			dohResolver := &DohResolver{URL: URL, Protocol: POST}
			if isJsonApi {
				dohResolver.Protocol = JsonAPI
			} else if isGet {
				dohResolver.Protocol = GET
			}
			resolver = dohResolver
		default:
			// unsupported protocol?
		}
	}

	if protocol != DOH {
		networkResolver := &NetworkResolver{Protocol: protocol}
		parseHostPort(networkResolver, rNetworkTokens)
		resolver = networkResolver
	}

	return
}

func parseHostPort(networkResolver *NetworkResolver, r string) {
	if host, port, err := net.SplitHostPort(r); err == nil {
		networkResolver.Host = host
		networkResolver.Port = port
	} else {
		networkResolver.Host = r
		if networkResolver.Protocol == DOT {
			networkResolver.Port = "853"
		} else {
			networkResolver.Port = "53"
		}
	}
}

func hasDohProtocol(resolver, protocol string) bool {
	return strings.HasSuffix(resolver, protocol)
}

func trimProtocol(resolver string) string {
	return stringsutil.TrimPrefixAny(resolver, TCP.StringWithSemicolon(), UDP.StringWithSemicolon(), DOH.StringWithSemicolon(), DOT.StringWithSemicolon())
}

func trimDohProtocol(resolver string) string {
	return stringsutil.TrimSuffixAny(resolver, GET.StringWithSemicolon(), POST.StringWithSemicolon(), JsonAPI.StringWithSemicolon())
}

func parseResolvers(resolvers []string) []Resolver {
	var parsedResolvers []Resolver
	for _, resolver := range resolvers {
		parsedResolvers = append(parsedResolvers, parseResolver(resolver))
	}
	return parsedResolvers
}
