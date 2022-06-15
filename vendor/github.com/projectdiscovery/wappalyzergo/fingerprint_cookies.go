package wappalyzer

import (
	"strings"
)

// checkCookies checks if the cookies for a target match the fingerprints
// and returns the matched IDs if any.
func (s *Wappalyze) checkCookies(cookies []string) []string {
	// Normalize the cookies for further processing
	normalized := s.normalizeCookies(cookies)

	technologies := s.fingerprints.matchMapString(normalized, cookiesPart)
	return technologies
}

const keyValuePairLength = 2

// normalizeCookies normalizes the cookies and returns an
// easily parsed format that can be processed upon.
func (s *Wappalyze) normalizeCookies(cookies []string) map[string]string {
	normalized := make(map[string]string)

	for _, part := range cookies {
		parts := strings.SplitN(strings.Trim(part, " "), "=", keyValuePairLength)
		if len(parts) < keyValuePairLength {
			continue
		}
		normalized[parts[0]] = parts[1]
	}
	return normalized
}

// findSetCookie finds the set cookie header from the normalized headers
func (s *Wappalyze) findSetCookie(headers map[string]string) []string {
	value, ok := headers["set-cookie"]
	if !ok {
		return nil
	}

	var values []string
	for _, v := range strings.Split(value, " ") {
		if v == "" {
			continue
		}
		if strings.Contains(v, ",") {
			values = append(values, strings.Split(v, ",")...)
		} else if strings.Contains(v, ";") {
			values = append(values, strings.Split(v, ";")...)
		} else {
			values = append(values, v)
		}
	}
	return values
}
