package jenkins

import (
	"fmt"
	"github.com/hktalent/scan4all/lib/util"
)

func Unauthorized(u string) bool {
	if req, err := util.HttpRequset(u, "GET", "", false, nil); err == nil {
		if req.Header.Get("X-Jenkins-Session") != "" {
			if req2, err := util.HttpRequset(u+"/script", "GET", "", false, nil); err == nil {
				if req2.StatusCode == 200 && util.StrContains(req2.Body, "Groovy script") {
					util.GoPocLog(fmt.Sprintf("Found vuln Jenkins Unauthorized script|%s\n", u+"/script"))
					return true
				}
			}
			if req2, err := util.HttpRequset(u+"/computer/(master)/scripts", "GET", "", false, nil); err == nil {
				if req2.StatusCode == 200 && util.StrContains(req2.Body, "Groovy script") {
					util.GoPocLog(fmt.Sprintf("Found vuln Jenkins Unauthorized script|%s\n", u+"/computer/(master)/scripts"))
					return true
				}
			}
		}
	}
	return false
}
