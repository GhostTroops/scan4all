package brute

import (
	"github.com/veo/vscan/pkg"
	"strings"
)

func File_fuzz(url string) (path []string) {
	if reqdir, err := pkg.HttpRequset(url+"/url_not_support/", "HEAD", "", false, nil); err == nil {
		if reqfile, err := pkg.HttpRequset(url+"/file_not_support", "HEAD", "", false, nil); err == nil {
			for _, urli := range filedic {
				lastword := urli[len(urli)-1:]
				switch urli {
				case "/manager/html":
					if req, err := pkg.HttpRequset(url+urli, "HEAD", "", false, nil); err == nil {
						if req.StatusCode == 401 && req.Header.Get("Www-Authenticate") != "" {
							path = append(path, urli)
						}
					}
				case "/console/login/LoginForm.jsp":
					if req, err := pkg.HttpRequset(url+urli, "GET", "", false, nil); err == nil {
						if req.StatusCode == 200 && strings.Contains(req.Body, "Oracle WebLogic Server Administration Console") {
							path = append(path, urli)
						}
					}

				case "/wls-wsat/CoordinatorPortType", "/_async/AsyncResponseService":
					if req, err := pkg.HttpRequset(url+urli, "GET", "", false, nil); err == nil {
						if req.StatusCode == 200 && strings.Contains(req.Body, "ws_utc") {
							path = append(path, urli)
						}
					}
				case "/seeyon/":
					if req, err := pkg.HttpRequset(url+urli, "GET", "", true, nil); err == nil {
						if strings.Contains(req.Body, "/seeyon/common/") {
							path = append(path, urli)
						}
					}
				default:
					if reqdir.StatusCode == 403 || reqfile.StatusCode == 403 {
						if req, err := pkg.HttpRequset(url+urli, "HEAD", "", false, nil); err == nil {
							if req.StatusCode == 200 {
								path = append(path, urli)
							}
						}
					} else {
						if req, err := pkg.HttpRequset(url+urli, "HEAD", "", false, nil); err == nil {
							if lastword == "/" && (req.StatusCode == 403 || req.StatusCode == 200) {
								path = append(path, urli)
							} else if req.StatusCode == 200 {
								path = append(path, urli)
							}
						}
					}
				}
			}
			if len(path) > 15 {
				path = nil
			}
		}
	}
	return path
}
