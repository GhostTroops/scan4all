package urlutil

import (
	"net/url"
	"strings"

	"github.com/projectdiscovery/stringsutil"
)

const (
	HTTP             = "http"
	HTTPS            = "https"
	schemeSeparator  = "://"
	DefaultHTTPPort  = "80"
	DefaultHTTPSPort = "443"
)

type URL struct {
	Scheme     string
	Username   string
	Password   string
	Host       string
	Port       string
	RequestURI string
	Fragment   string
}

func (u URL) String() string {
	var fullURL strings.Builder
	fullURL.WriteString(u.Scheme)
	fullURL.WriteString(schemeSeparator)
	if u.Username != "" {
		fullURL.WriteString(u.Username)
		if u.Password != "" {
			fullURL.WriteString(":" + u.Password)
		}
		fullURL.WriteString("@")
	}
	fullURL.WriteString(u.Host)
	if u.Port != "" {
		fullURL.WriteString(":" + u.Port)
	}
	fullURL.WriteString(u.RequestURI)
	if u.Fragment != "" {
		if u.RequestURI == "" {
			fullURL.WriteString("/")
		}
		fullURL.WriteString("#" + u.Fragment)
	}
	return fullURL.String()
}

func Parse(u string) (*URL, error) {
	return ParseWithScheme(u)
}

func ParseWithScheme(u string) (*URL, error) {
	// prepend default scheme if absent to increase parsing capabilities
	u = PreprendDefaultScheme(u)

	var origReqURI string
	U, err := url.Parse(u)
	if err != nil {
		// try to reparse without the request path
		// attempt to find the forward slash at the beginning of the path
		schemeDoubleForwardSlash := strings.Index(u, "//") + 2
		forwardSlashPosition := schemeDoubleForwardSlash + strings.Index(u[schemeDoubleForwardSlash:], "/")
		if forwardSlashPosition > 0 {
			origReqURI = u[forwardSlashPosition:]
			u = u[:forwardSlashPosition]
			U, err = url.Parse(u)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	// attempts to infer port
	port := U.Port()
	if port == "" {
		port = defaultPortForProtocol(U.Scheme)
	}

	// scheme
	scheme := U.Scheme

	// get host
	host := U.Host
	if port != "" {
		host = TrimPort(host, port)
	}

	// get credentials if any
	var username, password string
	if U.User != nil {
		username = U.User.Username()
		password, _ = U.User.Password()
	}

	// get full raw path
	var requri string
	// for our specific case we set this to empty if it equals to "/"
	if ruri := U.RequestURI(); ruri != "/" {
		requri = ruri
	}
	if origReqURI != "" && origReqURI != "/" {
		requri = origReqURI
	}

	// fragment
	fragment := U.Fragment

	return &URL{
		Scheme:     scheme,
		Host:       host,
		Username:   username,
		Password:   password,
		Port:       port,
		RequestURI: requri,
		Fragment:   fragment,
	}, nil
}

func PreprendDefaultScheme(u string) string {
	if stringsutil.HasPrefixI(u, HTTP+schemeSeparator) || stringsutil.HasPrefixI(u, HTTPS+schemeSeparator) {
		return u
	}

	return PreprendScheme(u, HTTPS)
}

func PreprendScheme(u, scheme string) string {
	if stringsutil.HasPrefixI(u, scheme+schemeSeparator) {
		return u
	}

	return scheme + schemeSeparator + u
}

func ChangePort(u, port string) (string, error) {
	U, err := Parse(u)
	if err != nil {
		return u, err
	}

	U.Port = port
	return U.String(), nil
}

func AppendRequestURI(u, requestURI string) (string, error) {
	U, err := Parse(u)
	if err != nil {
		return u, err
	}

	U.RequestURI += requestURI
	return U.String(), nil
}

func defaultPortForProtocol(protocol string) string {
	switch protocol {
	case HTTP:
		return DefaultHTTPPort
	case HTTPS:
		return DefaultHTTPSPort
	}

	return DefaultHTTPPort
}

func TrimPort(host, port string) string {
	return strings.TrimSuffix(host, ":"+port)
}

func TrimScheme(host string) string {
	r := strings.TrimPrefix(host, HTTP+schemeSeparator)
	r = strings.TrimPrefix(r, HTTPS+schemeSeparator)
	return r
}
