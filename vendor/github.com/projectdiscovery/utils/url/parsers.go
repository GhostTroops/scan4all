package urlutil

import (
	"net/url"
	"strings"

	"github.com/projectdiscovery/utils/errkit"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

// ## URL Parsing Methods

//  Function                                            | Description                                      | Type                          | Behavior                                 |
// -----------------------------------------------------|--------------------------------------------------|-------------------------------|------------------------------------------|
//  `Parse(inputURL string)`                            | Standard URL Parsing (+ Some Edgecases)          | Both Relative & Absolute URLs | NA                                       |
//  `ParseURL(inputURL string, unsafe bool)`            | Standard + Unsafe URL Parsing (+ Edgecases)      | Both Relative & Absolute URLs | NA                                       |
//  `ParseRelativeURL(inputURL string, unsafe bool)`    | Standard + Unsafe URL Parsing (+ Edgecases)      | Only Relative URLs            | error if absolute URL is given           |
//  `ParseRawRelativeURL(inputURL string, unsafe bool)` | Standard + Unsafe URL Parsing                    | Only Relative URLs            | error if absolute URL is given           |
//  `ParseAbsoluteURL(inputURL string, unsafe bool)`    | Standard + Unsafe URL Parsing (+ Edgecases)      | Only Absolute URLs            | error if relative URL is given           |

// ParseURL (can be relative or absolute)
func Parse(inputURL string) (*URL, error) {
	return ParseURL(inputURL, false)
}

// Parse and return URL (can be relative or absolute)
func ParseURL(inputURL string, unsafe bool) (*URL, error) {
	u := &URL{
		URL:      &url.URL{},
		Original: inputURL,
		Unsafe:   unsafe,
		Params:   NewOrderedParams(),
	}
	var err error
	u, err = absoluteURLParser(u)
	if err != nil {
		return nil, err
	}
	if u.IsRelative {
		return ParseRelativePath(inputURL, unsafe)
	}

	// logical bug url is not relative but host is empty
	if u.Host == "" {
		return nil, errkit.Newf("failed to parse url `%v`: got empty host when url is not relative", inputURL)
	}

	// # Normalization 1: if value of u.Host does not look like a common domain
	// it is most likely a relative path parsed as host
	// this happens because of ambiguity of url.Parse
	// because
	// when parsing url like scanme.sh/my/path url.Parse() puts `scanme.sh/my/path` as path and host is empty
	// to avoid this we always parse url with a schema prefix if it is missing (ex: https:// is not in input url) and then
	// rule out the possiblity that given url is not a relative path
	// this handles below edgecase
	// u , err :=  url.Parse(`mypath`)

	if !strings.Contains(u.Host, ".") && !strings.Contains(u.Host, ":") && u.Host != "localhost" {
		// TODO: should use a proper regex to validate hostname/ip
		// currently domain names without (.) are not considered as valid and autocorrected
		// this does not look like a valid domain , ipv4 or ipv6
		// consider it as relative
		// use ParseAbosluteURL to avoid this issue
		u.IsRelative = true
		u.Path = inputURL
		u.Host = ""
	}

	return u, nil
}

// ParseAbsoluteURL parses and returns absolute url
// should be preferred over others when input is known to be absolute url
// this reduces any normalization and autocorrection related to relative paths
// and returns error if input is relative path
func ParseAbsoluteURL(inputURL string, unsafe bool) (*URL, error) {
	u := &URL{
		URL:      &url.URL{},
		Original: inputURL,
		Unsafe:   unsafe,
		Params:   NewOrderedParams(),
	}
	var err error
	u, err = absoluteURLParser(u)
	if err != nil {
		return nil, err
	}
	if u.IsRelative {
		return nil, errkit.Newf("expected absolute url but got relative url input=%v,path=%v", inputURL, u.Path)
	}
	if u.Host == "" {
		return nil, errkit.Newf("something went wrong got empty host for absolute url=%v", inputURL)
	}
	return u, nil
}

// ParseRelativePath parses and returns relative path
// should be preferred over others when input is known to be relative path
// this reduces any normalization and autocorrection related to absolute paths
// and returns error if input is absolute path
func ParseRelativePath(inputURL string, unsafe bool) (*URL, error) {
	u := &URL{
		URL:        &url.URL{},
		Original:   inputURL,
		Unsafe:     unsafe,
		IsRelative: true,
	}
	return relativePathParser(u)
}

// ParseRelativePath
func ParseRawRelativePath(inputURL string, unsafe bool) (*URL, error) {
	u := &URL{
		URL:                &url.URL{},
		Original:           inputURL,
		Unsafe:             unsafe,
		IsRelative:         true,
		disableAutoCorrect: true,
	}
	return relativePathParser(u)
}

// absoluteURLParser is common absolute parser logic used to avoid duplication of code
func absoluteURLParser(u *URL) (*URL, error) {
	u.fetchParams()
	// filter out fragments and parameters only then parse path
	// we use u.Original because u.fetchParams() parses fragments and parameters
	// from u.Original (this is done to preserve query order in params and other edgecases)
	if u.Original == "" {
		return nil, errkit.New("failed to parse url got empty input")
	}

	// Note: we consider //scanme.sh as valid  (since all browsers accept this <script src="//ajax.googleapis.com/ajax/xx">)
	if strings.HasPrefix(u.Original, "/") && !strings.HasPrefix(u.Original, "//") {
		// this is definitely a relative path
		u.IsRelative = true
		u.Path = u.Original
		return u, nil
	}
	// Try to parse host related input
	allowedSchemes := []string{
		HTTP + SchemeSeparator,
		HTTPS + SchemeSeparator,
		WEBSOCKET + SchemeSeparator,
		WEBSOCKET_SSL + SchemeSeparator,
		FTP + SchemeSeparator,
		"//",
	}
	if strings.Contains(u.Original, SchemeSeparator) || strings.HasPrefix(u.Original, "//") {
		if !strings.HasPrefix(u.Original, "//") && !stringsutil.HasPrefixAny(u.Original, allowedSchemes...) {
			return nil, errkit.Newf("failed to parse url got invalid scheme input=%v", u.Original)
		}
		u.IsRelative = false
		urlparse, parseErr := url.Parse(u.Original)
		if parseErr != nil {
			// for parse errors in unsafe way try parsing again
			if u.Unsafe {
				urlparse = parseUnsafeFullURL(u.Original)
				if urlparse != nil {
					parseErr = nil
				}
			}
			if parseErr != nil {
				return nil, errkit.Wrap(parseErr, "failed to parse url")
			}
		}
		copy(u.URL, urlparse)
	} else {

		// try parsing with fallback if it is invalid URL escape error
		// split and read until first / and then parse the url
		parsed, err := url.Parse(HTTPS + SchemeSeparator + u.Original)
		if err != nil {
			if !strings.Contains(err.Error(), "invalid URL escape") {
				// if it is not a invalid URL escape error then it is most likely a relative path
				u.IsRelative = true
				return u, nil
			}
		} else {
			// successfully parsed absolute url
			parsed.Scheme = "" // remove newly added scheme
			copy(u.URL, parsed)
			return u, nil
		}

		// this is most likely a url of type scanme.sh/%2s/%invalid
		// if no prefix try to parse it with https
		// if failed we consider it as a relative path and not a full url
		pathIndex := strings.IndexRune(u.Original, '/')
		if pathIndex == -1 {
			// no path found most likely a relative path or localhost path
			urlparse, parseErr := url.Parse(HTTPS + SchemeSeparator + u.Original)
			if parseErr != nil {
				// most likely a relativeurls
				u.IsRelative = true
			} else {
				urlparse.Scheme = "" // remove newly added scheme
				copy(u.URL, urlparse)
			}
			return u, nil
		}
		// split until first / and then parse the url to handle invalid urls like
		// scnme.sh/xyz/%u2s/%invalid
		urlparse, parseErr := url.Parse(HTTPS + SchemeSeparator + u.Original[:pathIndex])
		if parseErr != nil {
			// most likely a relativeurls
			u.IsRelative = true
		} else {
			urlparse.Path = u.Original[pathIndex:]
			urlparse.Scheme = "" // remove newly added scheme
			copy(u.URL, urlparse)
		}
	}
	return u, nil
}

// relativePathParser is common relative path parser logic used to avoid duplication of code
func relativePathParser(u *URL) (*URL, error) {
	u.fetchParams()
	urlparse, parseErr := url.Parse(u.Original)
	if parseErr != nil {
		if !u.Unsafe {
			// should return error if not unsafe url
			return nil, errkit.Wrap(parseErr, "failed to parse input url")
		} else {
			// if unsafe do not rely on net/url.Parse
			u.Path = u.Original
		}
	}
	if urlparse != nil {
		urlparse.Host = ""
		copy(u.URL, urlparse)
	}
	u.parseUnsafeRelativePath()
	if u.Host != "" {
		return nil, errkit.Newf("expected relative path but got absolute path with host=%v,input=%v", u.Host, u.Original)
	}
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
