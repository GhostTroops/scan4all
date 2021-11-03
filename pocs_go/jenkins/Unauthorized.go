package jenkins

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func Unauthorized(u string) bool {
	if req, err := pkg.HttpRequset(u, "GET", "", false, nil); err == nil {
		if req.Header.Get("X-Jenkins-Session") != "" {
			if req2, err := pkg.HttpRequset(u+"/script", "GET", "", false, nil); err == nil {
				if req2.StatusCode == 200 && strings.Contains(req2.Body, "Groovy script") {
					pkg.GoPocLog(fmt.Sprintf("Found vuln Jenkins Unauthorized script|%s\n", u+"/script"))
					return true
				}
			}
			if req2, err := pkg.HttpRequset(u+"/computer/(master)/scripts", "GET", "", false, nil); err == nil {
				if req2.StatusCode == 200 && strings.Contains(req2.Body, "Groovy script") {
					pkg.GoPocLog(fmt.Sprintf("Found vuln Jenkins Unauthorized script|%s\n", u+"/computer/(master)/scripts"))
					return true
				}
			}
		}
	}
	return false
}
