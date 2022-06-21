package jboss

import (
	"fmt"
	"github.com/hktalent/scan4all/pkg"
)

func CVE_2017_12149(url string) bool {
	if req, err := pkg.HttpRequset(url+"/invoker/readonly", "GET", "", false, nil); err == nil {
		if req.StatusCode == 500 {
			pkg.GoPocLog(fmt.Sprintf("Found vuln Jboss CVE_2017_12149|%s\n", url))
			return true
		}
	}
	return false
}
