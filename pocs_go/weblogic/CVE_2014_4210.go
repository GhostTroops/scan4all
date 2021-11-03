package weblogic

import (
	"fmt"
	"github.com/veo/vscan/pkg"
)

func CVE_2014_4210(url string) bool {
	if req, err := pkg.HttpRequset(url+"/uddiexplorer/SearchPublicRegistries.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 {
			pkg.GoPocLog(fmt.Sprintf("Found vuln WebLogic CVE_2014_4210|%s\n", url))
			return true
		}
	}
	return false
}
