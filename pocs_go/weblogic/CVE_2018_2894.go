package weblogic

import (
	"fmt"
	"github.com/veo/vscan/pkg"
)

func CVE_2018_2894(url string) bool {
	if req, err := pkg.HttpRequset(url+"/ws_utc/begin.do", "GET", "", false, nil); err == nil {
		if req2, err2 := pkg.HttpRequset(url+"/ws_utc/config.do", "GET", "", false, nil); err2 == nil {
			if req.StatusCode == 200 || req2.StatusCode == 200 {
				pkg.GoPocLog(fmt.Sprintf("Found vuln WebLogic CVE_2018_2894|%s\n", url))
				return true
			}
		}
	}
	return false
}
