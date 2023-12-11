package jenkins

import (
	"github.com/GhostTroops/scan4all/lib/util"
)

func CVE_2018_1000110(u string) bool {
	if req, err := util.HttpRequset(u, "GET", "", false, nil); err == nil {
		if req.Header.Get("X-Jenkins-Session") != "" {
			if req2, err := util.HttpRequset(u+"/search/?q=a", "GET", "", false, nil); err == nil {
				if util.StrContains(req2.Body, "Search for 'a'") {
					util.SendLog(req.RequestUrl, "CVE-2018-1000110", "Found vuln Jenkins", "")
					return true
				}
			}
		}
	}
	return false
}
