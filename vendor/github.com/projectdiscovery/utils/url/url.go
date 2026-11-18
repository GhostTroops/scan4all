package urlutil

import (
	"bytes"
	"net"
	"net/url"
	"strings"

	osutils "github.com/projectdiscovery/utils/os"
)

// URL a wrapper around net/url.URL
type URL struct {
	*url.URL

	Original   string         // original or given url(without params if any)
	Unsafe     bool           // If request is unsafe (skip validation)
	IsRelative bool           // If URL is relative
	Params     *OrderedParams // Query Parameters
	// should call Update() method when directly updating wrapped url.URL or parameters
	disableAutoCorrect bool // when true any type of autocorrect is disabled
}

// mergepath merges given relative path
func (u *URL) MergePath(newrelpath string, unsafe bool) error {
	if newrelpath == "" {
		return nil
	}
	ux, err := ParseRelativePath(newrelpath, unsafe)
	if err != nil {
		return err
	}
	u.Params.Merge(ux.Params.Encode())
	u.Path = mergePaths(u.Path, ux.Path)
	if ux.Fragment != "" {
		u.Fragment = ux.Fragment
	}
	return nil
}

// UpdateRelPath updates relative path with new path (existing params are not removed)
func (u *URL) UpdateRelPath(newrelpath string, unsafe bool) error {
	u.Path = ""
	return u.MergePath(newrelpath, unsafe)
}

// Updates internal wrapped url.URL with any changes done to Query Parameters
func (u *URL) Update() {
	// This is a hot patch for url.URL
	// parameters are serialized when parsed with `url.Parse()` to avoid this
	// url should be parsed without parameters and then assigned with url.RawQuery to force unserialized parameters
	if u.Params != nil {
		u.RawQuery = u.Params.Encode()
	}
}

// Query returns Query Params
func (u *URL) Query() *OrderedParams {
	return u.Params
}

// Clone
func (u *URL) Clone() *URL {
	var userinfo *url.Userinfo
	if u.User != nil {
		// userinfo is immutable so this is the only way
		tempurl := HTTPS + SchemeSeparator + u.User.String() + "@" + "scanme.sh/"
		turl, _ := url.Parse(tempurl)
		if turl != nil {
			userinfo = turl.User
		}
	}
	ux := &url.URL{
		Scheme:      u.Scheme,
		Opaque:      u.Opaque,
		User:        userinfo,
		Host:        u.Host,
		Path:        u.Path,
		RawPath:     u.RawPath,
		RawQuery:    u.RawQuery,
		Fragment:    u.Fragment,
		OmitHost:    u.OmitHost, // only supported in 1.19
		ForceQuery:  u.ForceQuery,
		RawFragment: u.RawFragment,
	}
	params := u.Params.Clone()
	return &URL{
		URL:        ux,
		Params:     params,
		Original:   u.Original,
		Unsafe:     u.Unsafe,
		IsRelative: u.IsRelative,
	}
}

// String
func (u *URL) String() string {
	var buff bytes.Buffer
	if u.Scheme != "" && u.Host != "" {
		buff.WriteString(u.Scheme + "://")
	}
	if u.User != nil {
		buff.WriteString(u.User.String())
		buff.WriteRune('@')
	}
	buff.WriteString(u.Host)
	buff.WriteString(u.GetRelativePath())
	return buff.String()
}

// EscapedString returns a string that can be used as filename (i.e stripped of / and params etc)
func (u *URL) EscapedString() string {
	var buff bytes.Buffer
	host := u.Host
	if osutils.IsWindows() {
		host = strings.ReplaceAll(host, ":", "_")
	}
	buff.WriteString(host)
	if u.Path != "" && u.Path != "/" {
		buff.WriteString("_" + strings.ReplaceAll(u.Path, "/", "_"))
	}
	return buff.String()
}

// GetRelativePath ex: /some/path?param=true#fragment
func (u *URL) GetRelativePath() string {
	var buff bytes.Buffer
	if u.Path != "" {
		if !strings.HasPrefix(u.Path, "/") {
			buff.WriteRune('/')
		}
		buff.WriteString(u.Path)
	}
	if !u.Params.IsEmpty() {
		buff.WriteRune('?')
		buff.WriteString(u.Params.Encode())
	}
	if u.Fragment != "" {
		buff.WriteRune('#')
		buff.WriteString(u.Fragment)
	}
	return buff.String()
}

// Updates port
func (u *URL) UpdatePort(newport string) {
	if newport == "" {
		return
	}
	u.Host = net.JoinHostPort(u.Hostname(), newport)
}

// TrimPort if any
func (u *URL) TrimPort() {
	u.Host = u.Hostname()
}

// parseRelativePath parses relative path from Original Path without relying on
// net/url.URL
func (u *URL) parseUnsafeRelativePath() {
	// url.Parse discards %0a or any percent encoded characters from path
	// to avoid this if given url is not relative but has encoded chars
	// parse the path manually regardless if it is unsafe
	// ex: /%20test%0a =?
	// autocorrect if prefix is missing
	defer func() {
		// u.Path (stdlib) is vague related to path i.e `path (relative paths may omit leading slash)`
		// relative paths can have `/` prefix or not but this causes lot of edgecases as we have already
		// seen i.e why we have two dedicated parsers for this
		// ParseRelativePath --> always adds `/` if it is missing
		// ParseRawRelativePath --> No normalizations like adding `/`
		if !u.disableAutoCorrect && !strings.HasPrefix(u.Path, "/") && u.Path != "" {
			u.Path = "/" + u.Path
		}
	}()

	// check path integrity
	// url.parse() normalizes ../../ detect such cases are revert them
	if u.Original != u.Path {
		// params and fragements are removed from Original in Parsexx() therefore they can be compared
		u.Path = u.Original
	}

	// percent encoding in path
	if u.Host == "" || len(u.Host) < 4 {
		if shouldEscape(u.Original) {
			u.Path = u.Original
		}
		return
	}
	expectedPath := strings.SplitN(u.Original, u.Host, 2)
	if len(expectedPath) != 2 {
		// something went wrong fail silently
		return
	}
	u.Path = expectedPath[1]
}

// fetchParams retrieves query parameters from URL
func (u *URL) fetchParams() {
	if u.Params == nil {
		u.Params = NewOrderedParams()
	}
	// parse fragments if any
	if i := strings.IndexRune(u.Original, '#'); i != -1 {
		// assuming ?param=value#highlight
		u.Fragment = u.Original[i+1:]
		u.Original = u.Original[:i]
	}
	if index := strings.IndexRune(u.Original, '?'); index == -1 {
		return
	} else {
		encodedParams := u.Original[index+1:]
		u.Params.Decode(encodedParams)
		u.Original = u.Original[:index]
	}
	u.Update()
}

// copy parsed data from src to dst this does not include fragment or params
func copy(dst *url.URL, src *url.URL) {
	dst.Host = src.Host
	// dst.OmitHost = src.OmitHost // only supported in 1.19
	dst.Opaque = src.Opaque
	dst.Path = src.Path
	dst.RawPath = src.RawPath
	dst.Scheme = src.Scheme
	dst.User = src.User
}
