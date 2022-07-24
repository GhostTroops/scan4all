package jenkins

import (
	"fmt"
	"github.com/hktalent/scan4all/lib/util"
)

func CVE_2018_1000110(u string) bool {
	if req, err := util.HttpRequset(u, "GET", "", false, nil); err == nil {
		if req.Header.Get("X-Jenkins-Session") != "" {
			if req2, err := util.HttpRequset(u+"/search/?q=a", "GET", "", false, nil); err == nil {
				if util.StrContains(req2.Body, "Search for 'a'") {
					util.GoPocLog(fmt.Sprintf("Found vuln Jenkins CVE_2018_1000110|%s\n", u))
					return true
				}
			}
		}
	}
	return false
}
