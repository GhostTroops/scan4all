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

func FileFuzz(u string, indexStatusCode int, indexContentLength int, indexbody string) ([]string, []string) {
	var (
		path404              = "/file_not_support"
		page200CodeList      = []int{200, 301, 302}
		page404Title         = []string{"404", "不存在", "错误", "403", "禁止访问", "请求含有不合法的参数", "无法访问", "网络防火墙", "网站防火墙", "访问拦截", "由于安全原因JSP功能默认关闭"}
		page404Content       = []string{"<script>document.getElementById(\"a-link\").click();</script>", "404 Not Found", "您所提交的请求含有不合法的参数，已被网站管理员设置拦截", "404.safedog.cn"}
		page403title         = []string{"403", "Forbidden", "ERROR", "error"}
		page403Content       = []string{"403", "Forbidden", "ERROR", "error"}
		location404          = []string{"/auth/login/", "error.html"}
		payloadlocation404   []string
		payload200Title      []string
		payload200Contentlen []int
		skip403              = false
		skip302              = false
		other200Contentlen   []int
		other200Title        []string
		errorTimes           = 0
		technologies         []string
		path                 []string
	)
	other200Contentlen = append(other200Contentlen, indexContentLength)
	other200Title = append(other200Title, gettitle(indexbody))
	if url404, url404req, err := reqPage(u + path404); err == nil {
		if url404req.StatusCode == 404 {
			technologies = addfingerprints404(technologies, url404req) //基于404页面文件扫描指纹添加
		}
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
			return path, technologies
		}
		//if (pkg.StringInSlice("/1.asp", path) && pkg.StringInSlice("/1.jsp", path) && pkg.StringInSlice("/2.jsp", path)) || (pkg.StringInSlice("/1.php", path) && pkg.StringInSlice("/1.jsp", path) && pkg.StringInSlice("/2.jsp", path)) || (pkg.StringInSlice("/zabbix/", path) && pkg.StringInSlice("/grafana/", path) && pkg.StringInSlice("/zentao/", path)) {
		//	return nil, nil
		//}
		if len(path) > 40 {
			return path, technologies
		}
		ch <- struct{}{}
		go func(payload string) {
			if url, req, err := reqPage(u + payload); err == nil {
				if url.is403 && (pkg.SliceInString(url.title, page403title) || pkg.SliceInString(req.Body, page403Content)) && !skip403 {
					path = append(path, payload)
					technologies = addfingerprints403(payload, technologies) // 基于403页面文件扫描指纹添加
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
					if pkg.SliceInString(req.Location, location404) && pkg.SliceInString(req.Location, payloadlocation404) {
						is404Page = true
					}
					if !strings.HasSuffix(req.Location, payload+"/") {
						location404 = append(payloadlocation404, req.Location)
						is404Page = true
					}
				}

				if !is404Page {
					for _, title := range other200Title {
						if len(url.title) > 2 && url.title == title {
							is404Page = true
						}
					}
					for _, title := range payload200Title {
						if len(url.title) > 2 && url.title == title {
							is404Page = true
						}
					}
					for _, l := range other200Contentlen {
						reqlenabs := req.ContentLength - l
						if reqlenabs < 0 {
							reqlenabs = -reqlenabs
						}
						if reqlenabs <= 5 {
							is404Page = true
						}
					}
					for _, l := range payload200Contentlen {
						reqlenabs := req.ContentLength - l
						if reqlenabs < 0 {
							reqlenabs = -reqlenabs
						}
						if reqlenabs <= 5 {
							is404Page = true
						}
					}
					payload200Title = append(payload200Title, url.title)
					payload200Contentlen = append(payload200Contentlen, req.ContentLength)
					if !is404Page {
						path = append(path, payload)
						technologies = addfingerprintsnormal(payload, technologies, req) // 基于200页面文件扫描指纹添加
					}
				}
			} else {
				errorTimes += 1
			}
			<-time.After(time.Duration(500) * time.Millisecond)
			<-ch
		}(payload)
	}
	close(ch)
	return path, technologies
}
