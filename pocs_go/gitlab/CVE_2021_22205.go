package gitlab

import (
	"bytes"
	"github.com/GhostTroops/scan4all/lib/util"
	"mime/multipart"
	"net/textproto"
	"regexp"
)

func CVE_2021_22205(url string) bool {
	if req, err := util.HttpRequset(url+"/users/sign_in", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 {
			var cookie string
			var csrf string
			if req.Header != nil {
				var SetCookieAll string
				for i := range (*req.Header)["Set-Cookie"] {
					SetCookieAll += (*req.Header)["Set-Cookie"][i]
				}
				cookie = regexp.MustCompile("_gitlab_session=(.*?);").FindString(SetCookieAll)
				//if len(counts) > 1 {
				//	cookie = counts[1]
				//}
			}
			if req.Body != "" {
				csrfToken := regexp.MustCompile("<meta name=\"csrf-token\" content=\"(.*?)\"").FindStringSubmatch(req.Body)
				if len(csrfToken) > 1 {
					csrf = csrfToken[1]
				}
			}
			if cookie != "" && csrf != "" {
				return upload(url, cookie, csrf)
			}
		}
	}
	return false
}

func upload(u string, cookie string, csrf string) bool {
	buf := new(bytes.Buffer)
	w := multipart.NewWriter(buf)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="file"; filename="1.jpg"`)
	h.Set("Content-Type", "image/jpeg")
	fw, err := w.CreatePart(h)
	if err != nil {
		return false
	}
	_, _ = fw.Write([]byte("1"))
	boundary := w.Boundary()
	_ = w.Close()
	header := make(map[string]string)
	header["Content-Type"] = "multipart/form-data; boundary=" + boundary
	header["Cookie"] = cookie
	header["X-CSRF-Token"] = csrf
	if req, err := util.HttpRequset(u+"/uploads/user", "POST", buf.String(), false, header); err == nil {
		if util.StrContains(req.Body, "Failed to process image") {
			util.SendLog(req.RequestUrl, "CVE-2021-22205", "Found vuln gitlab ", buf.String())
			return true
		}
	}
	return false
}
