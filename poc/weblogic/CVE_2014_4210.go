package weblogic

import (
	"fmt"
	"github.com/veo/vscan/pkg"
)

func CVE_2014_4210(url string) bool {
	if req, err := pkg.HttpRequset(url+"/uddiexplorer/SearchPublicRegistries.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 {
			fmt.Printf("weblogic-exp-sucess|CVE_2014_4210|%s\n", url)
			return true
		}
	}
	return false
}
