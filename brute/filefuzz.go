package brute

import (
	"github.com/veo/vscan/pkg"
	"regexp"
	"strings"
	"time"
)

type page struct {
	isBackUpPath bool
	isBackUpPage bool
	title        string
	locationUrl  string
	is302        bool
	is403        bool
}

func gettitle(body string) string {
	domainreg2 := regexp.MustCompile(`<title>([\s\S]{1,200})</title>`)
	titlelist := domainreg2.FindStringSubmatch(body)
	if len(titlelist) > 1 {
		return titlelist[1]
	}
	return ""
}

func reqPage(u string) (*page, *pkg.Response, error) {
	page := &page{}
	var backUpSuffixList = []string{".tar", ".tar.gz", ".zip", ".rar", ".7z", ".bz2", ".gz", ".war"}
	var method = "GET"

	for _, ext := range backUpSuffixList {
		if strings.HasSuffix(u, ext) {
			page.isBackUpPath = true
			method = "HEAD"
		}
	}
	if req, err := pkg.HttpRequset(u, method, "", false, nil); err == nil {
		if pkg.IntInSlice(req.StatusCode, []int{301, 302, 307, 308}) {
			page.is302 = true
		}
		page.title = gettitle(req.Body)
		page.locationUrl = req.Location
		regs := []string{"text/plain", "application/.*download", "application/.*file", "application/.*zip", "application/.*rar", "application/.*tar", "application/.*down", "application/.*compressed", "application/stream"}
		for _, reg := range regs {
			matched, _ := regexp.Match(reg, []byte(req.Header.Get("Content-Type")))
			if matched {
				page.isBackUpPage = true
			}
		}
		if req.StatusCode == 403 && strings.HasSuffix(u, "/") {
			page.is403 = true
		}
		return page, req, err
	} else {
		return page, nil, err
	}
}

func FileFuzz(u string, indexStatusCode int, indexContentLength int, indexbody string) (path []string, technologies []string) {
	var path404 = "/file_not_support"
	var page200CodeList = []int{200, 301, 302, 401, 500}
	var page404Title = []string{"404", "不存在", "错误", "403", "禁止访问", "请求含有不合法的参数", "网络防火墙", "网站防火墙", "访问拦截", "由于安全原因JSP功能默认关闭"}
	var page404Content = []string{"<script>document.getElementById(\"a-link\").click();</script>", "404 Not Found", "您所提交的请求含有不合法的参数，已被网站管理员设置拦截"}
	var page403title = []string{"403", "Forbidden", "ERROR"}
	var page403Content = []string{"403", "Forbidden", "ERROR"}
	var location404 = []string{"/auth/login/", "error.html"}
	var skip403 = false
	var skip302 = false
	var other200Contentlen []int
	var other200Title []string
	var errorTimes = 0
	other200Contentlen = append(other200Contentlen, indexContentLength)
	other200Title = append(other200Title, gettitle(indexbody))
	if url404, url404req, err := reqPage(u + path404); err == nil {

		//基于404页面文件扫描指纹添加
		if url404req.StatusCode == 404 && strings.Contains(url404req.Body, "thinkphp") {
			technologies = append(technologies, "ThinkPHP")
		}
		//

		if url404.is302 {
			location404 = append(location404, url404.locationUrl)
		}
		if url404.is302 && strings.HasSuffix(url404.locationUrl, "/file_not_support/") {
			skip302 = true
		}
		if url404.is403 || indexStatusCode == 403 {
			skip403 = true
		}
		if url404req.StatusCode == 200 {
			other200Title = append(other200Title, url404.title)
			other200Contentlen = append(other200Contentlen, url404req.ContentLength)
		}
	}
	ch := make(chan struct{}, 20)
	for _, payload := range filedic {
		var is404Page = false
		if errorTimes > 20 {
			return
		}
		if (pkg.StringInSlice("/1.asp", path) && pkg.StringInSlice("/1.jsp", path) && pkg.StringInSlice("/2.jsp", path)) || (pkg.StringInSlice("/1.php", path) && pkg.StringInSlice("/1.jsp", path) && pkg.StringInSlice("/2.jsp", path)) || (pkg.StringInSlice("/zabbix/", path) && pkg.StringInSlice("/grafana/", path) && pkg.StringInSlice("/zentao/", path)) {
			return nil, nil
		}
		ch <- struct{}{}
		go func(payload string) {
			if url, req, err := reqPage(u + payload); err == nil {
				if url.is403 && (pkg.SliceInString(url.title, page403title) || pkg.SliceInString(req.Body, page403Content)) && !skip403 {
					// 基于403页面文件扫描指纹添加
					switch payload {
					case "/Runtime/Logs/":
						technologies = append(technologies, "ThinkPHP")
					}
					path = append(path, payload)
				}
				if !pkg.IntInSlice(req.StatusCode, page200CodeList) {
					is404Page = true
				}
				if url.isBackUpPath {
					if !url.isBackUpPage {
						is404Page = true
					}
				}
				if pkg.SliceInString(url.title, page404Title) {
					is404Page = true
				}
				if pkg.SliceInString(req.Body, page404Content) {
					is404Page = true
				}
				if strings.Contains(req.RequestUrl, "/.") && req.StatusCode == 200 {
					if req.ContentLength == 0 {
						is404Page = true
					}
				}
				if url.is302 {
					if skip302 {
						is404Page = true
					}
					if pkg.SliceInString(req.Location, location404) {
						is404Page = true
					}
					if !strings.HasSuffix(req.Location, payload+"/") {
						location404 = append(location404, req.Location)
						is404Page = true
					}
				}

				if !is404Page {
					for _, title := range other200Title {
						if len(url.title) > 2 && url.title == title {
							is404Page = true
						}
					}
					for _, len := range other200Contentlen {
						reqlenabs := req.ContentLength - len
						if reqlenabs < 0 {
							reqlenabs = -reqlenabs
						}
						if reqlenabs <= 5 {
							is404Page = true
						}
					}
					other200Title = append(other200Title, url.title)
					other200Contentlen = append(other200Contentlen, req.ContentLength)
					if !is404Page {
						// 基于200页面文件扫描指纹添加
						switch payload {
						case "/manager/html":
							if req.StatusCode == 401 && req.Header.Get("Www-Authenticate") != "" {
								technologies = append(technologies, "Apache Tomcat")
							}
						case "/console/login/LoginForm.jsp":
							if req.StatusCode == 200 && strings.Contains(req.Body, "Oracle WebLogic Server Administration Console") {
								technologies = append(technologies, "weblogic")
							}
						case "/wls-wsat/CoordinatorPortType", "/_async/AsyncResponseService":
							if req.StatusCode == 200 && strings.Contains(req.Body, "ws_utc") {
								technologies = append(technologies, "weblogic")
							}
						case "/seeyon/":
							if strings.Contains(req.Body, "/seeyon/common/") {
								technologies = append(technologies, "seeyon")
							}
						case "/admin/":
							if strings.Contains(req.Body, "pass") || strings.Contains(req.Body, "Pass") || strings.Contains(req.Body, "PASS") {
								technologies = append(technologies, "admin登录页")
							}
						case "/zabbix/":
							if strings.Contains(req.Body, "www.zabbix.com") {
								technologies = append(technologies, "zabbix")
							}
						case "/grafana/":
							if strings.Contains(req.Body, "grafana-app") {
								technologies = append(technologies, "Grafana")
							}
						case "/zentao/":
							if strings.Contains(req.Body, "zentao/theme") {
								technologies = append(technologies, "zentao")
							}
						case "/actuator", "/actuator/archaius", "/actuator/auditevents", "/actuator/autoconfig", "/actuator/bindings", "/actuator/caches", "/actuator/channels", "/actuator/conditions", "/actuator/configprops", "/actuator/env", "/actuator/env.json", "/actuator/gateway/globalfilters", "/actuator/gateway/routefilters", "/actuator/gateway/routes", "/actuator/health", "/actuator/health.json", "/actuator/heapdump", "/actuator/hystrix.stream", "/actuator/integrationgraph", "/actuator/mappings", "/actuator/metrics", "/actuator/routes", "/actuator/scheduledtasks", "/actuator/service-registry":
							technologies = append(technologies, "Spring")
						}
						path = append(path, payload)
					}
				}
			} else {
				errorTimes += 1
			}
			<-time.After(time.Duration(1000) * time.Millisecond)
			<-ch
		}(payload)
	}
	return path, technologies
}
