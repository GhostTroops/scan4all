package jboss

import (
	"github.com/GhostTroops/scan4all/lib/util"
)

func CVE_2017_12149(url string) bool {
	if req, err := util.HttpRequset(url+"/invoker/readonly", "GET", "", false, nil); err == nil {
		if req.StatusCode == 500 {
			util.SendLog(req.RequestUrl, "CVE-2017-12149", "Found vuln Jboss", "")
			return true
		}
	}
	return false
}
