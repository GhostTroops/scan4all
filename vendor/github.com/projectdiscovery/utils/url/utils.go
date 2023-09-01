package urlutil

import (
	"os"
	"strings"

	errorutil "github.com/projectdiscovery/utils/errors"
)

const (
	HTTP             = "http"
	HTTPS            = "https"
	SchemeSeparator  = "://"
	DefaultHTTPPort  = "80"
	DefaultHTTPSPort = "443"
)

// AutoMergeRelPaths merges two relative paths including parameters and returns final string
func AutoMergeRelPaths(path1 string, path2 string) (string, error) {
	if path1 == "" || path2 == "" {
		// no need to parse
		return mergePaths(path1, path2), nil
	}
	u1, err1 := ParseRelativePath(path1, true)
	if err1 != nil {
		return "", err1
	}
	u2, err2 := ParseRelativePath(path2, true)
	if err2 != nil {
		return "", err2
	}
	u1.Params.Merge(u2.Params.Encode())
	err := u1.MergePath(u2.Path, false)
	return u1.GetRelativePath(), err
}

// mergePaths merges two relative paths
func mergePaths(elem1 string, elem2 string) string {
	// if both have slash remove one
	if strings.HasSuffix(elem1, "/") && strings.HasPrefix(elem2, "/") {
		elem2 = strings.TrimLeft(elem2, "/")
	}

	if elem1 == "" {
		return elem2
	} else if elem2 == "" {
		return elem1
	}

	// if both paths donot have a slash add it to beginning of second
	if !strings.HasSuffix(elem1, "/") && !strings.HasPrefix(elem2, "/") {
		elem2 = "/" + elem2
	}

	// Do not normalize but combibe paths same as path.join
	// Merge Examples (Same as path.Join)
	// /blog   /admin => /blog/admin
	// /blog/wp /wp-content  => /blog/wp/wp-content
	// /blog/admin /blog/admin/profile => /blog/admin/profile
	// /blog/admin /blog => /blog/admin/blog
	// /blog /blog/ => /blog/

	if elem1 == elem2 {
		return elem1
	} else if len(elem1) > len(elem2) && strings.HasSuffix(elem1, elem2) {
		return elem1
	} else if len(elem1) < len(elem2) && strings.HasPrefix(elem2, elem1) {
		return elem2
	} else {
		return elem1 + elem2
	}
}

// ShouldEscapes returns true if given payload contains any characters
// that are not accepted by url or must be escaped
// this does not include seperators
func shouldEscape(ss string) bool {
	rmap := getrunemap(RFCEscapeCharSet)
	for _, v := range ss {
		switch {
		case v == '/':
			continue
		case v > rune(127):
			return true
		default:
			if _, ok := rmap[v]; ok {
				return true
			}
		}
	}
	return false
}

func init() {
	if os.Getenv("DEBUG") != "" {
		errorutil.ShowStackTrace = true
	}
}
