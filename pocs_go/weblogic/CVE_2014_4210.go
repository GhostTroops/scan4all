package weblogic

import (
	"fmt"
	"github.com/hktalent/scan4all/pkg"
)

func CVE_2014_4210(url string) bool {
	if req, err := pkg.HttpRequset(url+"/uddiexplorer/SearchPublicRegistries.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 {
			pkg.GoPocLog(fmt.Sprintf("Found vuln Weblogic CVE_2014_4210|%s\n", url))
			return true
		}
	}
	return false
}
