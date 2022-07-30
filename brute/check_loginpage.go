package brute

import (
	"github.com/hktalent/scan4all/lib/util"
	"net/url"
	"regexp"
	"strings"
)

func CheckLoginPage(inputurl string) bool {
	if req, err := util.HttpRequset(inputurl, "GET", "", true, nil); err == nil {
		cssurl := regexp.MustCompile(`<link[^>]*href=['"](.*?)['"]`).FindAllStringSubmatch(req.Body, -1)
		for _, v := range cssurl {
			if strings.Contains(v[1], ".css") {
				u, err := url.Parse(strings.TrimSpace(inputurl))
				if err != nil {
					return false
				}
				href, err := url.Parse(strings.TrimSpace(v[1]))
				if err != nil {
					return false
				}
				if err != nil {
					return false
				}
				hrefurl := u.ResolveReference(href)
				if reqcss, err := util.HttpRequset(hrefurl.String(), "GET", "", true, nil); err == nil {
					if util.StrContains(reqcss.Body, "login") {
						return true
					}
				}
			}
		}
		return false
	}
	return false
}
