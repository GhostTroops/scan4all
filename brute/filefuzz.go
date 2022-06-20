package brute

import (
	_ "embed"
	"github.com/antlabs/strsim"
	"github.com/hktalent/scan4all/pkg"
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

// 获取标题
func gettitle(body string) string {
	domainreg2 := regexp.MustCompile(`<title>([^<]*)</title>`)
	titlelist := domainreg2.FindStringSubmatch(body)
	if len(titlelist) > 1 {
		return titlelist[1]
	}
	return ""
}

//go:embed dicts/bakSuffix.txt
var bakSuffix string

//go:embed dicts/fuzzContentType1.txt
var fuzzct string

func reqPage(u string) (*page, *pkg.Response, error) {
	page := &page{}
	var backUpSuffixList = strings.Split(strings.TrimSpace(bakSuffix), "\n")
	var method = "GET"

	for _, ext := range backUpSuffixList {
		if strings.HasSuffix(u, ext) {
			page.isBackUpPath = true
			method = "HEAD"
		}
	}
	header := make(map[string]string)
	header["Accept"] = "text/html,*/*;"
	if req, err := pkg.HttpRequset(u, method, "", false, header); err == nil {
		if pkg.IntInSlice(req.StatusCode, []int{301, 302, 307, 308}) {
			page.is302 = true
		}
		page.title = gettitle(req.Body)
		page.locationUrl = req.Location
		regs := strings.Split(strings.TrimSpace(fuzzct), "\n")
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

//go:embed dicts/fuzz404.txt
var fuzz404 string

//go:embed dicts/page404Content.txt
var page404Content1 string

// 文件fuzz
func FileFuzz(u string, indexStatusCode int, indexContentLength int, indexbody string) ([]string, []string) {
	var (
		path404            = "/file_not_support"
		page200CodeList    = []int{200, 301, 302}
		page404Title       = strings.Split(strings.TrimSpace(fuzz404), "\n")
		page404Content     = strings.Split(strings.TrimSpace(page404Content1), "\n")
		page403title       = []string{"403", "Forbidden", "ERROR", "error"}
		page403Content     = []string{"403", "Forbidden", "ERROR", "error"}
		location404        = []string{"/auth/login/", "error.html"}
		payloadlocation404 []string
		payload200Title    []string
		skip403            = false
		skip302            = false
		errorTimes         = 0
		technologies       []string
		path               []string
		page404Len         int    // 404 page length
		page404Body        string // 404 url
	)
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
			page404Title = append(page404Title, url404.title)
			page404Len = url404req.ContentLength
			page404Body = url404req.Body
		}
	}
	ch := make(chan struct{}, pkg.Fuzzthreads)
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
					path = append(path, u+payload)
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
					// 不是很明白，为什么和历史title差不多就是404？
					//for _, title := range payload200Title {
					//	if len(url.title) > 2 && url.title == title {
					//		is404Page = true
					//	}
					//}
					//// 与 404，index页面做比较, 个字节差别，认定为 404
					//if 5 > (req.ContentLength-page404Len)-(len(req.RequestUrl)-len(page404Url)) {
					//	is404Page = true
					//}
					//for _, l := range other200Contentlen { // 这里的代码确实没有看明白，为什么要和index的长度判断为404
					//	reqlenabs := req.ContentLength - l
					//	if reqlenabs < 0 {
					//		reqlenabs = -reqlenabs
					//	}
					//	if reqlenabs <= 5 {
					//		is404Page = true
					//	}
					//}
					// 和404页面 90%相似度，则认为是404
					if page404Len > 0 && req.ContentLength > 0 && 0.9 < strsim.Compare(page404Body, req.Body) {
						is404Page = true
					}
					payload200Title = append(payload200Title, url.title)
					if !is404Page {
						path = append(path, u+payload)
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
