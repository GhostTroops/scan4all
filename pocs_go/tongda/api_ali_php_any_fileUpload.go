package tongda

import (
	"github.com/GhostTroops/scan4all/lib/util"
)

// version 通达 OA V11.8 api.ali.php 任意文件上传
func File_upload(url string) bool {
	if req, err := util.HttpRequset(url+"/mobile/api/api.ali.php", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 {
			util.SendLog(req.RequestUrl, "File_upload", "Found vuln  tongda-OA upload in api.ali.php", "")
			return true
		}
	}
	return false
}
