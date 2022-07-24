package weblogic

import (
	"fmt"
	"github.com/hktalent/scan4all/lib/util"
)

func CVE_2018_2894(url string) bool {
	if req, err := util.HttpRequset(url+"/ws_utc/begin.do", "GET", "", false, nil); err == nil {
		if req2, err2 := util.HttpRequset(url+"/ws_utc/config.do", "GET", "", false, nil); err2 == nil {
			if req.StatusCode == 200 || req2.StatusCode == 200 {
				util.GoPocLog(fmt.Sprintf("Found vuln Weblogic CVE_2018_2894|%s\n", url))
				return true
			}
		}
	}
	return false
}
