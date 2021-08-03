package weblogic

import (
	"fmt"
	"github.com/veo/vscan/poc"
)

func CVE_2014_4210(url string) bool {
	if req, err := poc.HttpRequset(url+"/uddiexplorer/SearchPublicRegistries.jsp", "GET", ""); err == nil {
		if req.StatusCode == 200 {
			fmt.Printf("weblogic-exp-sucess|CVE_2014_4210|%s\n", url)
			return true
		}
	}
	return false
}
