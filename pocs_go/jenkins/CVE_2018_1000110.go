package jenkins

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func CVE_2018_1000110(u string) bool {
	if req, err := pkg.HttpRequset(u, "GET", "", false, nil); err == nil {
		if req.Header.Get("X-Jenkins-Session") != "" {
			if req2, err := pkg.HttpRequset(u+"/search/?q=a", "GET", "", false, nil); err == nil {
				if strings.Contains(req2.Body, "Search for 'a'") {
					pkg.GoPocLog(fmt.Sprintf("Found vuln Jenkins CVE_2018_1000110|%s\n", u))
					return true
				}
			}
		}
	}
	return false
}
