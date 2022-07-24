package weblogic

import (
	"fmt"
	"github.com/hktalent/scan4all/lib/util"
)

func CVE_2014_4210(url string) bool {
	if req, err := util.HttpRequset(url+"/uddiexplorer/SearchPublicRegistries.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 {
			util.GoPocLog(fmt.Sprintf("Found vuln Weblogic CVE_2014_4210|%s\n", url))
			return true
		}
	}
	return false
}
