package brute

import (
	"fmt"
	"github.com/hktalent/scan4all/pkg"
	"strings"
)

func Weblogic_brute(url string) (username string, password string) {
	if req, err := pkg.HttpRequset(url+"/console/login/LoginForm.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 {
			for uspa := range weblogicuserpass {
				if req2, err2 := pkg.HttpRequset(url+"/console/j_security_check", "POST", fmt.Sprintf("j_username=%s&j_password=%s", weblogicuserpass[uspa].username, weblogicuserpass[uspa].password), true, nil); err2 == nil {
					if strings.Contains(req2.RequestUrl, "console.portal") {
						pkg.BurteLog(fmt.Sprintf("Found vuln Weblogic password|%s:%s|%s\n", weblogicuserpass[uspa].username, weblogicuserpass[uspa].password, url+"/console/"))
						return weblogicuserpass[uspa].username, weblogicuserpass[uspa].password
					}
				}
			}
			return "login_page", ""
		}
	}
	return "", ""
}
