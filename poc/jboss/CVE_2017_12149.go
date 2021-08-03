package jboss

import (
	"fmt"
	"github.com/veo/vscan/poc"
)

func CVE_2017_12149(url string) bool {
	if req, err := poc.HttpRequset(url+"/invoker/readonly", "GET", ""); err == nil {
		if req.StatusCode == 500 {
			fmt.Printf("jboss-exp-sucess|CVE_2017_12149|%s\n", url)
			return true
		}
	}
	return false
}
