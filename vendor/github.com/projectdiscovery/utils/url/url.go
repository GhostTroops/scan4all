package urlutil

import (
	"bytes"
	"net/url"
	"strings"

	errorutil "github.com/projectdiscovery/utils/errors"
	osutils "github.com/projectdiscovery/utils/os"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

// disables autocorrect related to parsing
// Ex: if input is admin url.Parse considers admin as host which is not a valid domain name
var DisableAutoCorrect bool

// URL a wrapper around net/url.URL
type URL struct {
	*url.URL

	Original   string         // original or given url(without params if any)
	Unsafe     bool           // If request is unsafe (skip validation)
	IsRelative bool           // If URL is relative
	Params     *OrderedParams // Query Parameters
	// should call Update() method when directly updating wrapped url.URL or parameters
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
		Scheme:   u.Scheme,
		Opaque:   u.Opaque,
		User:     userinfo,
		Host:     u.Host,
		Path:     u.Path,
		RawPath:  u.RawPath,
		RawQuery: u.RawQuery,
		Fragment: u.Fragment,
		// OmitHost:    u.OmitHost, // only supported in 1.19
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
	if u.Scheme != "" {
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
	if u.Params.om.Len() > 0 {
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
	if u.URL.Port() != "" {
		u.Host = strings.Replace(u.Host, u.Port(), newport, 1)
		return
	}
	u.Host += ":" + newport
}

// TrimPort if any
func (u *URL) TrimPort() {
	u.URL.Host = u.Hostname()
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
		if !strings.HasPrefix(u.Path, "/") && u.Path != "" {
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

// ParseURL
func Parse(inputURL string) (*URL, error) {
	return ParseURL(inputURL, false)
}

// Parse and return URL
func ParseURL(inputURL string, unsafe bool) (*URL, error) {
	u := &URL{
		URL:      &url.URL{},
		Original: inputURL,
		Unsafe:   unsafe,
		Params:   NewOrderedParams(),
	}
	u.fetchParams()
	// filter out fragments and parameters only then parse path
	inputURL = u.Original
	if inputURL == "" {
		return nil, errorutil.NewWithTag("urlutil", "failed to parse url got empty input")
	}

	// Note: we consider //scanme.sh as valid  (since all browsers accept this <script src="//ajax.googleapis.com/ajax/xx">)
	if strings.HasPrefix(inputURL, "/") && !strings.HasPrefix(inputURL, "//") {
		// this is definitely a relative path
		u.IsRelative = true
		u.Path = u.Original
		return u, nil
	}
	// Try to parse host related input
	if stringsutil.HasPrefixAny(inputURL, HTTP+SchemeSeparator, HTTPS+SchemeSeparator, "//") || strings.Contains(inputURL, "://") {
		u.IsRelative = false
		urlparse, parseErr := url.Parse(inputURL)
		if parseErr != nil {
			// for parse errors in unsafe way try parsing again
			if unsafe {
				urlparse = parseUnsafeFullURL(inputURL)
				if urlparse != nil {
					parseErr = nil
				}
			}
			if parseErr != nil {
				return nil, errorutil.NewWithErr(parseErr).Msgf("failed to parse url")
			}
		}
		copy(u.URL, urlparse)
	} else {
		// if no prefix try to parse it with https
		// if failed we consider it as a relative path and not a full url
		urlparse, parseErr := url.Parse(HTTPS + SchemeSeparator + inputURL)
		if parseErr != nil {
			// most likely a relativeurl
			u.IsRelative = true
			// TODO: investigate if prefix / should be added
		} else {
			urlparse.Scheme = "" // remove newly added scheme
			copy(u.URL, urlparse)
		}
	}

	// try parsing path
	if !u.IsRelative {
		// if parsing is successful validate and autocorrect
		//ex: when inputURL is admin `url.Parse()` considers admin as Host with parsed with https://
		// i.e https://admin which is not valid/accepted domain
		//TODO: Properly Validate using regex
		if u.Host == "" {
			// this is unexpected case return err
			return nil, errorutil.NewWithTag("urlutil", "failed to parse url %v got empty host", inputURL)
		}
		// TODO: should use a proper regex to validate hostname/ip
		// currently domain names without (.) are not considered as valid and autocorrected
		// if DisableAutoCorrect is false
		if !strings.Contains(u.Host, ".") && !strings.Contains(u.Host, ":") && u.Host != "localhost" {
			// this does not look like a valid domain , ipv4 or ipv6
			// consider it as relative
			if !DisableAutoCorrect {
				u.IsRelative = true
				u.Path = inputURL
				u.Host = ""
			}
		}
	}
	if !u.IsRelative && u.Host == "" {
		return nil, errorutil.NewWithTag("urlutil", "failed to parse url `%v`", inputURL).Msgf("got empty host when url is not relative")
	}
	if u.IsRelative {
		return ParseRelativePath(inputURL, unsafe)
	}
	return u, nil
}

// ParseRelativePath parses and returns relative path
func ParseRelativePath(inputURL string, unsafe bool) (*URL, error) {
	u := &URL{
		URL:        &url.URL{},
		Original:   inputURL,
		Unsafe:     unsafe,
		IsRelative: true,
	}
	u.fetchParams()
	urlparse, parseErr := url.Parse(inputURL)
	if parseErr != nil {
		if !unsafe {
			// should return error if not unsafe url
			return nil, errorutil.NewWithErr(parseErr).WithTag("urlutil").Msgf("failed to parse input url")
		} else {
			// if unsafe do not rely on net/url.Parse
			u.Path = inputURL
		}
	}
	if urlparse != nil {
		urlparse.Host = ""
		copy(u.URL, urlparse)
	}
	u.parseUnsafeRelativePath()
	return u, nil
}

// parseUnsafeFullURL parses invalid(unsafe) urls (ex: https://scanme.sh/%invalid)
// this is not supported as per RFC and url.Parse fails
func parseUnsafeFullURL(urlx string) *url.URL {
	// we only allow unsupported chars in path
	// since url.Parse() returns error there isn't any standard way to do this
	// Current methodology
	// 1. temp replace `//` schema seperator to avoid collisions
	// 2. get first index of `/` i.e path seperator (if none skip any furthur preprocessing)
	// 3. if found split urls into base and path (i.e https://scanme.sh/%invalid => `https://scanme.sh`+`/%invalid`)
	// 4. Host part is parsed by net/url.URL and path is parsed manually
	temp := strings.Replace(urlx, "//", "", 1)
	index := strings.IndexRune(temp, '/')
	if index == -1 {
		return nil
	}
	urlPath := temp[index:]
	urlHost := strings.TrimSuffix(urlx, urlPath)
	parseURL, parseErr := url.Parse(urlHost)
	if parseErr != nil {
		return nil
	}
	if relpath, err := ParseRelativePath(urlPath, true); err == nil {
		parseURL.Path = relpath.Path
		return parseURL
	}
	return nil
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
