package weblogic

import (
	"fmt"
	"github.com/veo/vscan/poc"
)

func CVE_2018_2894(url string) bool {
	if req, err := poc.HttpRequset(url+"/ws_utc/begin.do", "GET", ""); err == nil {
		if req2, err2 := poc.HttpRequset(url+"/ws_utc/config.do", "GET", ""); err2 == nil {
			if req.StatusCode == 200 || req2.StatusCode == 200 {
				fmt.Printf("weblogic-exp-sucess|CVE_2018_2894|%s\n", url)
				return true
			}
		}
	}
	return false
}
