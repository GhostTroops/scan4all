package brute

import (
	"github.com/veo/vscan/pkg"
	"regexp"
	"strings"
)

func File_fuzz(url string) (path []string) {
	if reqdir, err := pkg.HttpRequset(url+"/url_not_support/", "GET", "", false, nil); err == nil {
		if reqfile, err := pkg.HttpRequset(url+"/file_not_support", "GET", "", false, nil); err == nil {
			if reqfile.StatusCode == 404 && strings.Contains(reqfile.Body, "thinkphp") {
				path = append(path, "/ThinkPHP")
			}
			for _, urli := range filedic {
				lastword := urli[len(urli)-1:]
				switch urli {
				case "/www.zip", "/www.rar", "/www.7z", "/www.tar.gz", "/www.tar", "/web.zip", "/web.rar", "/web.7z", "/web.tar.gz", "/web.tar", "/wwwroot.zip", "/wwwroot.rar", "/wwwroot.7z", "/wwwroot.tar.gz", "/wwwroot.tar", "/data.zip", "/data.rar", "/data.7z", "/data.tar.gz", "/data.tar":
					if req, err := pkg.HttpRequset(url+urli, "HEAD", "", false, nil); err == nil {
						if req.StatusCode == 200 {
							regs := []string{"text/plain", "application/.*download", "application/.*file", "application/.*zip", "application/.*rar", "application/.*tar", "application/.*down", "application/.*compressed", "application/stream"}
							for _, reg := range regs {
								matched, _ := regexp.Match(reg, []byte(req.Header.Get("Content-Type")))
								if matched {
									path = append(path, urli)
								}
							}
						}
					}
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
				case "/admin/":
					if req, err := pkg.HttpRequset(url+urli, "GET", "", true, nil); err == nil {
						if strings.Contains(req.Body, "pass") || strings.Contains(req.Body, "Pass") || strings.Contains(req.Body, "PASS") {
							path = append(path, urli)
						}
					}
				case "/zabbix/":
					if req, err := pkg.HttpRequset(url+urli, "GET", "", true, nil); err == nil {
						if strings.Contains(req.Body, "www.zabbix.com") {
							path = append(path, urli)
						}
					}
				case "/grafana/":
					if req, err := pkg.HttpRequset(url+urli, "GET", "", true, nil); err == nil {
						if strings.Contains(req.Body, "grafana-app") {
							path = append(path, urli)
						}
					}
				case "/zentao/":
					if req, err := pkg.HttpRequset(url+urli, "GET", "", true, nil); err == nil {
						if strings.Contains(req.Body, "zentao/theme") {
							path = append(path, urli)
						}
					}
				case "/Runtime/Logs/":
					if req, err := pkg.HttpRequset(url+urli, "HEAD", "", false, nil); err == nil {
						if req.StatusCode == 403 {
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
