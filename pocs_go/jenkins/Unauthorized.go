package jenkins

import (
	"github.com/GhostTroops/scan4all/lib/util"
)

func Unauthorized(u string) bool {
	if req, err := util.HttpRequset(u, "GET", "", false, nil); err == nil {
		if req.Header.Get("X-Jenkins-Session") != "" {
			if req2, err := util.HttpRequset(u+"/script", "GET", "", false, nil); err == nil {
				if req2.StatusCode == 200 && util.StrContains(req2.Body, "Groovy script") {
					util.SendLog(req.RequestUrl, "CVE-2018-10003000", "Found vuln Jenkins Unauthorized", "")
					return true
				}
			}
			if req2, err := util.HttpRequset(u+"/computer/(master)/scripts", "GET", "", false, nil); err == nil {
				if req2.StatusCode == 200 && util.StrContains(req2.Body, "Groovy script") {
					util.SendLog(req.RequestUrl, "CVE-2018-10003000", "Found vuln Jenkins Unauthorized script", "")
					return true
				}
			}
		}
	}
	return false
}
