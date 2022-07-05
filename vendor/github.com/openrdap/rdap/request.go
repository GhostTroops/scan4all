// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

package rdap

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// A RequestType specifies an RDAP request type.
type RequestType uint8

const (
	_ RequestType = iota
	AutnumRequest
	DomainRequest
	EntityRequest
	HelpRequest
	IPRequest
	NameserverRequest

	DomainSearchRequest
	DomainSearchByNameserverRequest
	DomainSearchByNameserverIPRequest
	NameserverSearchRequest
	NameserverSearchByNameserverIPRequest
	EntitySearchRequest
	EntitySearchByHandleRequest

	// RawRequest is a request with a fixed RDAP URL.
	RawRequest
)

// String returns the RequestType as a string.
// e.g. "autnum", "domain", "help".
func (r RequestType) String() string {
	switch r {
	case AutnumRequest:
		return "autnum"
	case DomainRequest:
		return "domain"
	case EntityRequest:
		return "entity"
	case HelpRequest:
		return "help"
	case IPRequest:
		return "ip"
	case NameserverRequest:
		return "nameserver"
	case DomainSearchRequest:
		return "domain-search"
	case DomainSearchByNameserverRequest:
		return "domain-search-by-nameserver"
	case DomainSearchByNameserverIPRequest:
		return "domain-search-by-nameserver-ip"
	case NameserverSearchRequest:
		return "nameserver-search"
	case NameserverSearchByNameserverIPRequest:
		return "nameserver-search-by-ip"
	case EntitySearchRequest:
		return "entity-search"
	case EntitySearchByHandleRequest:
		return "entity-search-by-handle"
	case RawRequest:
		return "url"
	default:
		panic("Unknown RequestType")
	}
}

// A Request represents an RDAP request.
//
//   req := &rdap.Request{
//     Type: rdap.DomainRequest,
//     Query: "example.cz",
//   }
//
// RDAP supports many request types. These are:
//
//   RequestType                                | Bootstrapped? | HTTP request path       | Example Query
//   -------------------------------------------+---------------+-------------------------+----------------
//   rdap.AutnumRequest                         | Yes           | autnum/QUERY            | AS2846
//   rdap.DomainRequest                         | Yes           | domain/QUERY            | example.cz
//   rdap.EntityRequest                         | Experimental  | entity/QUERY            | 86860670-VRSN
//   rdap.HelpRequest                           | No            | help                    | N/A
//   rdap.IPRequest                             | Yes           | ip/QUERY                | 2001:db8::1
//   rdap.NameserverRequest                     | No            | nameserver/QUERY        | ns1.skip.org
//                                              |               |                         |
//   rdap.DomainSearchRequest                   | No            | domains?name=QUERY      | exampl*.com
//   rdap.DomainSearchByNameserverRequest       | No            | domains?nsLdhName=QUERY | ns1.exampl*.com
//   rdap.DomainSearchByNameserverIPRequest     | No            | domains?nsIp=QUERY      | 192.0.2.0
//   rdap.NameserverSearchRequest               | No            | nameservers?name=QUERY  | ns1.exampl*.com
//   rdap.NameserverSearchByNameserverIPRequest | No            | nameservers?ip=QUERY    | 192.0.2.0
//   rdap.EntitySearchRequest                   | No            | entities?fn=QUERY       | ABC*-VRSN
//   rdap.EntitySearchByHandleRequest           | No            | entities?handle=QUERY   | ABC*-VRSN
//                                              |               |                         |
//   rdap.RawRequest                            | N/A           | N/A                     | N/A
//
// See https://tools.ietf.org/html/rfc7482 for more information on RDAP request
// types.
//
// Requests are executed by a Client. To execute a Request, an RDAP server is
// required. The servers for Autnum, IP, and Domain queries are determined
// automatically via bootstrapping (a lookup at https://data.iana.org/rdap/).
//
// For other Request types, you must specify the RDAP server:
//
//   // Nameserver query on rdap.nic.cz.
//   server, _ := url.Parse("https://rdap.nic.cz")
//   req := &rdap.Request{
//     Type: rdap.NameserverRequest,
//     Query: "a.ns.nic.cz",
//
//     Server: server,
//   }
//
// RawRequest is a special case for existing RDAP request URLs:
//   rdapURL, _ := url.Parse("https://rdap.example/mystery/query?ip=192.0.2.0")
//   req := &rdap.Request{
//     Type: rdap.RawRequest,
//     Server: rdapURL,
//   }
type Request struct {
	// Request type.
	Type RequestType

	// Request query text.
	Query string

	// Optional URL query parameters to include in the RDAP request.
	//
	// These are added to the URL returned by URL().
	Params url.Values

	// Optional RDAP server URL.
	//
	// If present, specifies the RDAP server to execute the Request on.
	// Otherwise, nil enables bootstrapping.
	//
	// For Type=RawRequest, this specifies the full RDAP URL instead (with the
	// Query/Params fields not used).
	Server *url.URL

	// Optional list of contact roles. This enables additional HTTP requests for
	// these contact roles, to obtain full contact information.
	//
	// The common WHOIS contact roles are "registrant", "administrative", and
	// "billing".
	//
	// RDAP responses may contain full contact information (such as domain
	// registrant name & address), or just a URL to it. For convenience,
	// applications may prefer to receive the full contact information.
	//
	// The FetchRoles option enables additional HTTP requests for contact
	// information. Additional HTTP requests are made for URL-only contact roles
	// matching the FetchRoles list. Additional information is then merged into
	// the Response.
	//
	// Specify a list of contact roles for which additional HTTP requests may be
	// made. The default is no extra fetches. Use the special string "all" to
	// fetch all available contact information.
	FetchRoles []string

	// Maximum request duration before timeout.
	//
	// The default is no timeout.
	Timeout time.Duration

	ctx context.Context
}

func (r *Request) pathAndValues() (string, url.Values) {
	path := ""
	values := url.Values{}

	switch r.Type {
	case AutnumRequest:
		path = fmt.Sprintf("autnum/%s", escapePath(r.Query))
	case DomainRequest:
		path = fmt.Sprintf("domain/%s", escapePath(r.Query))
	case EntityRequest:
		path = fmt.Sprintf("entity/%s", escapePath(r.Query))
	case HelpRequest:
		path = "help"
	case IPRequest:
		// TODO: escape IP address/nets?
		path = fmt.Sprintf("ip/%s", r.Query)
	case NameserverRequest:
		path = fmt.Sprintf("nameserver/%s", escapePath(r.Query))
	case DomainSearchRequest:
		path = "domains"
		values["name"] = []string{r.Query}
	case DomainSearchByNameserverRequest:
		path = "domains"
		values["nsLdhName"] = []string{r.Query}
	case DomainSearchByNameserverIPRequest:
		path = "domains"
		values["nsIp"] = []string{r.Query}
	case NameserverSearchRequest:
		path = "nameservers"
		values["name"] = []string{r.Query}
	case NameserverSearchByNameserverIPRequest:
		path = "nameservers"
		values["ip"] = []string{r.Query}
	case EntitySearchRequest:
		path = "entities"
		values["fn"] = []string{r.Query}
	case EntitySearchByHandleRequest:
		path = "entities"
		values["handle"] = []string{r.Query}
	case RawRequest:
		// Server URL(s) are the entire request.
	default:
		panic("unknown QueryType")
	}

	return path, values
}

// URL constructs and returns the RDAP Request URL.
//
// As an example:
//   server, _ := url.Parse("https://rdap.nic.cz")
//   req := &rdap.Request{
//     Type: rdap.NameserverRequest,
//     Query: "a.ns.nic.cz",
//
//     Server: server,
//   }
//
//   fmt.Println(req.URL()) // Prints https://rdap.nic.cz/nameserver/a.ns.nic.cz.
//
// Returns nil if the Server field is nil.
//
// For Type=RawRequest, the Server field is returned unmodified.
func (r *Request) URL() *url.URL {
	if r.Server == nil {
		return nil
	}

	path, values := r.pathAndValues()

	var resultURL *url.URL

	if r.Type == RawRequest {
		resultURL = new(url.URL)
		*resultURL = *r.Server
	} else {
		tempURL := &*r.Server
		tempURL.RawQuery = ""
		tempURL.Fragment = ""
		tempURLString := tempURL.String()

		if len(tempURLString) == 0 || tempURLString[len(tempURLString)-1] != '/' {
			tempURLString += "/"
		}

		tempURLString += path

		var err error
		resultURL, err = url.Parse(tempURLString)

		if err != nil {
			return nil
		}

		query := r.Server.Query()
		for k, v := range r.Params {
			query[k] = v
		}
		for k, v := range values {
			query[k] = v
		}
		resultURL.RawQuery = query.Encode()

		resultURL.Fragment = r.Server.Fragment
	}

	return resultURL
}

// WithContext returns a copy of the Request, with Context |ctx|.
func (r *Request) WithContext(ctx context.Context) *Request {
	r2 := new(Request)
	*r2 = *r
	r2.ctx = ctx

	return r2
}

// Context returns the Request's context.
//
// The returned context is always non-nil; it defaults to the background context.
func (r *Request) Context() context.Context {
	if r.ctx == nil {
		return context.Background()
	}

	return r.ctx
}

// WithServer returns a copy of the Request, with the Server set to |server|.
func (r *Request) WithServer(server *url.URL) *Request {
	r2 := new(Request)
	*r2 = *r
	r2.Server = server

	return r2
}

func escapePath(text string) string {
	var escaped []byte

	for i := 0; i < len(text); i++ {
		b := text[i]

		if !shouldPathEscape(b) {
			escaped = append(escaped, b)
		} else {
			escaped = append(escaped, '%',
				"0123456789ABCDEF"[b>>4],
				"0123456789ABCDEF"[b&0xF],
			)
		}
	}

	return string(escaped)
}

func shouldPathEscape(b byte) bool {
	if ('A' <= b && b <= 'Z') || ('a' <= b && b <= 'z') || ('0' <= b && b <= '9') {
		return false
	}

	switch b {
	case '-', '_', '.', '~', '$', '&', '+', ':', '=', '@':
		return false
	}

	return true
}

// NewHelpRequest creates a new help Request.
//
// The RDAP server must be specified.
func NewHelpRequest() *Request {
	return &Request{
		Type: HelpRequest,
	}
}

// NewAutnumRequest creates a new Request for the AS number |asn|.
func NewAutnumRequest(asn uint32) *Request {
	return &Request{
		Type:  AutnumRequest,
		Query: fmt.Sprintf("%d", asn),
	}
}

// NewIPRequest creates a new Request for the IP address |ip|.
func NewIPRequest(ip net.IP) *Request {
	return &Request{
		Type:  IPRequest,
		Query: ip.String(),
	}
}

// NewIPNetRequest creates a new Request for the IP network |net|.
func NewIPNetRequest(net *net.IPNet) *Request {
	return &Request{
		Type:  IPRequest,
		Query: net.String(),
	}
}

// NewDomainRequest creates a new Request for the domain name |domain|.
func NewDomainRequest(domain string) *Request {
	return &Request{
		Type:  DomainRequest,
		Query: domain,
	}
}

// NewEntityRequest creates a new Request for the entity name |entity|.
//
// The RDAP server must be specified.
func NewEntityRequest(entity string) *Request {
	return &Request{
		Type:  EntityRequest,
		Query: entity,
	}
}

// NewNameserverRequest creates a new Request for the nameserver |nameserver|.
//
// The RDAP server must be specified.
func NewNameserverRequest(nameserver string) *Request {
	return &Request{
		Type:  NameserverRequest,
		Query: nameserver,
	}
}

// NewRawRequest creates a Request from the URL |rdapURL|.
//
// When a client executes the Request, it will fetch |rdapURL|.
func NewRawRequest(rdapURL *url.URL) *Request {
	return &Request{
		Type:   RawRequest,
		Server: rdapURL,
	}
}

// NewRequest creates a new Request with type |requestType| and |query| text.
//
// Depending on the |requestType|, the RDAP server may need to be specified.
func NewRequest(requestType RequestType, query string) *Request {
	return &Request{
		Type:  requestType,
		Query: query,
	}
}

// NewAutoRequest creates a Request by guessing the type required for |queryText|.
//
// The following types are suppported:
//  - RawRequest    - e.g. https://example.com/domain/example2.com
//  - DomainRequest - e.g. example.com, https://example.com, http://example.com/
//  - IPRequest     - e.g. 192.0.2.0, 2001:db8::, 192.0.2.0/24, 2001:db8::/128
//  - AutnumRequest - e.g. AS2856, 5400
//  - EntityRequest - all other queries.
//
// Returns a Request. Use r.Type to find the RequestType chosen.
func NewAutoRequest(queryText string) *Request {
	// Full RDAP URL?
	fullURL, err := url.Parse(queryText)
	if err == nil && (fullURL.Scheme == "http" || fullURL.Scheme == "https") {
		// Parse "http://example.com/" as a domain query for convenience.
		if fullURL.Path == "" || fullURL.Path == "/" {
			return NewDomainRequest(fullURL.Host)
		}

		return NewRawRequest(fullURL)
	}

	// IP address?
	ip := net.ParseIP(queryText)
	if ip != nil {
		return NewIPRequest(ip)
	}

	// IP network?
	_, ipNet, err := net.ParseCIDR(queryText)
	if ipNet != nil {
		return NewIPNetRequest(ipNet)
	}

	// AS number? (formats: AS1234, as1234, 1234).
	autnum, err := parseAutnum(queryText)
	if err == nil {
		return NewAutnumRequest(autnum)
	}

	// Looks like a domain name?
	if strings.Contains(queryText, ".") {
		return NewDomainRequest(queryText)
	}

	// Otherwise call it an entity query.
	return NewEntityRequest(queryText)
}

func parseAutnum(autnum string) (uint32, error) {
	autnum = strings.ToUpper(autnum)
	autnum = strings.TrimPrefix(autnum, "AS")
	result, err := strconv.ParseUint(autnum, 10, 32)

	if err != nil {
		return 0, err
	}

	return uint32(result), nil
}
