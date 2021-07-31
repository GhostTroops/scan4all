package tomcat

import "github.com/veo/vscan/exp"

func CVE_2017_12615(url string) bool {
	if req, err := exp.HttpRequset(url+"/vscan.txt", "PUT", "vscana"); err == nil {
		if req.StatusCode == 204 || req.StatusCode == 201 {
			return true
		}
	}
	return false
}
