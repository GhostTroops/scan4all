package cdncheck

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

var suffixToSource map[string]string

// cdnWappalyzerTechnologies contains a map of wappalyzer technologies to cdns
var cdnWappalyzerTechnologies = map[string]string{
	"imperva":    "imperva",
	"incapsula":  "incapsula",
	"cloudflare": "cloudflare",
	"cloudfront": "amazon",
	"akamai":     "akamai",
}

// CheckFQDN checks if fqdns are known cloud ones
func (c *Client) CheckSuffix(fqdns ...string) (isCDN bool, provider string, itemType string, err error) {
	c.Once.Do(func() {
		suffixToSource = make(map[string]string)
		for source, suffixes := range generatedData.Common {
			for _, suffix := range suffixes {
				suffixToSource[suffix] = source
			}
		}
	})
	for _, fqdn := range fqdns {
		parsed, err := publicsuffix.Parse(fqdn)
		if err != nil {
			return false, "", "", errors.Wrap(err, "could not parse fqdn")
		}
		if discovered, ok := suffixToSource[parsed.TLD]; ok {
			return true, discovered, "waf", nil
		}
		domain := parsed.SLD + "." + parsed.TLD
		if discovered, ok := suffixToSource[domain]; ok {
			return true, discovered, "waf", nil
		}
	}
	return false, "", "", nil
}

// CheckWappalyzer checks if the wappalyzer detection are a part of CDN
func (c *Client) CheckWappalyzer(data map[string]struct{}) (isCDN bool, provider string, err error) {
	for technology := range data {
		if strings.Contains(technology, ":") {
			if parts := strings.SplitN(technology, ":", 2); len(parts) == 2 {
				technology = parts[0]
			}
		}
		technology = strings.ToLower(technology)
		if discovered, ok := cdnWappalyzerTechnologies[technology]; ok {
			return true, discovered, nil
		}
	}
	return false, "", nil
}
