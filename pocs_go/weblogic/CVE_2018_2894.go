package weblogic

import (
	"github.com/GhostTroops/scan4all/lib/util"
)

func CVE_2018_2894(url string) bool {
	if req, err := util.HttpRequset(url+"/ws_utc/begin.do", "GET", "", false, nil); err == nil {
		if req2, err2 := util.HttpRequset(url+"/ws_utc/config.do", "GET", "", false, nil); err2 == nil {
			if req.StatusCode == 200 || req2.StatusCode == 200 {
				util.SendLog(req.RequestUrl, "CVE-2018-2894", "Found vuln Weblogic", "")
				return true
			}
		}
	}
	return false
}
