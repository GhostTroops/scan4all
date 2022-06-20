package brute

import (
	"github.com/hktalent/scan4all/pkg"
	"net/url"
	"regexp"
	"strings"
)

func CheckLoginPage(inputurl string) bool {
	if req, err := pkg.HttpRequset(inputurl, "GET", "", true, nil); err == nil {
		cssurl := regexp.MustCompile(`<link[^>]*href=['"](.*?)['"]`).FindAllStringSubmatch(req.Body, -1)
		for _, v := range cssurl {
			if strings.Contains(v[1], ".css") {
				u, err := url.Parse(inputurl)
				if err != nil {
					return false
				}
				href, err := url.Parse(v[1])
				if err != nil {
					return false
				}
				if err != nil {
					return false
				}
				hrefurl := u.ResolveReference(href)
				if reqcss, err := pkg.HttpRequset(hrefurl.String(), "GET", "", true, nil); err == nil {
					if strings.Contains(reqcss.Body, "login") || strings.Contains(reqcss.Body, "Login") {
						return true
					}
				}
			}
		}
		return false
	}
	return false
}
