package brute

import (
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
)

func Tomcat_brute(url string) (username string, password string) {
	if req, err := util.HttpRequsetBasic("asdasdascsacacs", "asdasdascsacacs", url+"/manager/html", "HEAD", "", false, nil); err == nil {
		if req.StatusCode == 401 {
			for uspa := range tomcatuserpass {
				if req2, err2 := util.HttpRequsetBasic(tomcatuserpass[uspa].username, tomcatuserpass[uspa].password, url+"/manager/html", "HEAD", "", false, nil); err2 == nil {
					if req2.StatusCode == 200 || req2.StatusCode == 403 {
						util.SendLog(req2.RequestUrl, "tomcat_brute", fmt.Sprintf("Found vuln Tomcat password|%s:%s|%s\n", tomcatuserpass[uspa].username, tomcatuserpass[uspa].password, url), "")
						return tomcatuserpass[uspa].username, tomcatuserpass[uspa].password
					}
				}
			}
		}
	}
	return "", ""
}
