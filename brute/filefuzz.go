package brute

import (
	_ "embed"
	"github.com/antlabs/strsim"
	"github.com/hktalent/scan4all/pkg"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

// fuzz请求返回的结果
// 尽可能使用指针，节约内存开销
type Page struct {
	isBackUpPath bool          // 备份、敏感泄露文件检测请求url
	isBackUpPage bool          // 发现备份、敏感泄露文件
	title        *string       // 标题
	locationUrl  *string       // 跳转页面
	is302        bool          // 是302页面
	is403        bool          // 403页面
	Url          *string       // 作为本地永久缓存key，提高执行效率
	BodyStr      *string       // body = trim() + ToLower
	BodyLen      int           // body 长度
	Header       *http.Header  // 基于指针，节约内存空间
	StatusCode   int           // 状态码
	Resqonse     *pkg.Response // 基于指针，节约内存空间
}

// 备份、敏感文件后缀
//go:embed dicts/bakSuffix.txt
var bakSuffix string

// 404url,智能学习
//go:embed dicts/404url.txt
var sz404Url string

// 备份、敏感文件 http头类型 ContentType 检测
//go:embed dicts/fuzzContentType1.txt
var fuzzct string

// 敏感文件前缀
//go:embed dicts/prefix.txt
var szPrefix string

var (
	ret            = []string{} // 敏感信息文件字典
	prefix, suffix []string     // 敏感信息字典: 前缀、后缀
	asz404Url      []string     // 404url,智能学习
)

// 生成敏感信息字典
func InitGeneral() int {
	szPrefix = pkg.GetVal4File("prefix", szPrefix)
	prefix = strings.Split(strings.TrimSpace(szPrefix), "\n")
	suffix = strings.Split(strings.TrimSpace(bakSuffix), "\n")

	for i := 0; i < len(prefix); i++ {
		for j := 0; j < len(suffix); j++ {
			ret = append(ret, "/"+prefix[i]+suffix[j])
		}
	}
	eableFileFuzz = !pkg.GetValAsBool("enablFileFuzz")
	return len(ret)
}

// 请求url并返回自定义对象
func reqPage(u string) (*Page, *pkg.Response, error) {
	page := &Page{Url: &u}
	var method = "GET"
	for _, ext := range suffix {
		if strings.HasSuffix(u, ext) {
			page.isBackUpPath = true
			method = "HEAD" // 节约请求时间
		}
	}
	header := make(map[string]string)
	header["Accept"] = "*/*"
	header["Connection"] = "close"
	header["Pragma"] = "no-cache"
	// fuzz check Shiro CVE_2016_4437
	header["Cookie"] = "JSESSIONID=" + RandStr4Cookie + ";rememberMe=123"
	if req, err := pkg.HttpRequset(u, method, "", false, header); err == nil && nil != req && nil != req.Header {
		//if pkg.IntInSlice(req.StatusCode, []int{301, 302, 307, 308}) {
		// 简单粗暴效率高
		if 300 <= req.StatusCode && req.StatusCode < 400 {
			page.is302 = true
		}
		page.StatusCode = req.StatusCode
		page.Resqonse = req
		page.Header = req.Header
		page.BodyLen = len(req.Body)
		page.title = Gettitle(req.Body)
		page.locationUrl = &req.Location
		//  敏感文件头信息检测
		page.isBackUpPage = CheckBakPage(req)
		// https://zh.m.wikipedia.org/zh-hans/HTTP_403
		// 403 Forbidden 是HTTP协议中的一个HTTP状态码（Status Code）。403状态码意为服务器成功解析请求但是客户端没有访问该资源的权限
		page.is403 = req.StatusCode == 403
		return page, req, err
	} else {
		return page, nil, err
	}
}

// 敏感文件头信息检测:
//  检测头信息是否有敏感文件、本份文件、流文件等敏感信息
func CheckBakPage(req *pkg.Response) bool {
	if x0, ok := (*req.Header)["Content-Type"]; ok && 0 < len(x0) {
		x0B := []byte(x0[0])
		for _, reg := range regs {
			// 找到对应等正则
			if r1, ok := regsMap[reg]; ok {
				if r1.Match(x0B) {
					return true
				}
			}
		}
	}
	return false
}

//go:embed dicts/fuzz404.txt
var fuzz404 string

//go:embed dicts/page404Content.txt
var page404Content1 string

// 备份、敏感文件 http头类型 ContentType 检测,正则
var regs []string

var (
	regsMap                      = make(map[string]*regexp.Regexp) // fuzz 正则库
	page404Title, page404Content []string                          // 404 标题库、正文库
	eableFileFuzz                = false                           // 是否开启fuzz
)

// 初始化字典、数组等
func init() {
	bakSuffix = pkg.GetVal4File("bakSuffix", bakSuffix)
	fuzzct = pkg.GetVal4File("fuzzct", fuzzct)
	fuzz404 = pkg.GetVal4File("fuzz404", fuzz404)
	fuzz404 = pkg.GetVal4File("fuzz404", fuzz404)
	sz404Url = pkg.GetVal4File("404url", sz404Url)
	asz404Url = strings.Split(strings.TrimSpace(sz404Url), "\n")
	page404Content1 = pkg.GetVal4File("page404Content1", page404Content1)
	page404Title = strings.Split(strings.TrimSpace(fuzz404), "\n")
	page404Content = strings.Split(strings.TrimSpace(page404Content1), "\n")
	InitGeneral()
	regs = strings.Split(strings.TrimSpace(fuzzct), "\n")
	var err error
	// 初始化多时候一次性编译，否则会影响效率
	for _, reg := range regs {
		regsMap[reg], err = regexp.Compile(reg)
		if nil != err {
			log.Println(reg, " regexp.Compile error: ", err)
		}
	}
	//regs = append(regs, ret...)
}

// 绝对404请求文件前缀
var file_not_support = "file_not_support"

// 绝对404请求文件
var RandStr = file_not_support + "_scan4all"

// 随机10个字符串
var RandStr4Cookie = pkg.RandStringRunes(10)

// 重写了fuzz：优化流程、优化算法、修复线程安全bug、增加智能功能
func FileFuzz(u string, indexStatusCode int, indexContentLength int, indexbody string) ([]string, []string) {
	if eableFileFuzz {
		return []string{}, []string{}
	}
	u01, err := url.Parse(u)
	if nil == err {
		u = u01.Scheme + "://" + u01.Host + "/"
	}
	var (
		path404               = RandStr // 绝对404页面路径
		errorTimes   int32    = 0       // 错误计数器，> 20则退出fuzz
		technologies []string           // 指纹数据
		path         []string           // 成功页面路径
	)
	url404, url404req, err := reqPage(u + path404)
	if err == nil {
		// 其实这里无论状态码是什么，都是404
		// 所有异常页面 > 400 > 500都做异常页面fuzz指纹
		if url404req.StatusCode > 400 {
			technologies = Addfingerprints404(technologies, url404req, url404) //基于404页面文件扫描指纹添加
		}
	}
	var wg sync.WaitGroup
	// 中途控制关闭当前目标所有fuzz
	var CloseAll = make(chan struct{})
	// 控制 fuzz 线程数
	var ch = make(chan struct{}, pkg.Fuzzthreads)
	// 异步接收结果
	wg.Add(1)
	var async_data = make(chan []string, 64)
	var async_technologies = make(chan []string, 64)
	defer func() {
		pkg.CloseChan(ch)
		close(async_data)
		close(async_technologies)
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-CloseAll:
				return
			case x1 := <-async_data:
				path = append(path, x1...)
				if len(path) > 40 {
					pkg.CloseChan(CloseAll)
					atomic.AddInt32(&errorTimes, 21)
				}
			case x2 := <-async_technologies:
				technologies = append(technologies, x2...)
			}
		}
	}()

	for _, payload := range filedic {
		// 接收到停止信号
		if atomic.LoadInt32(&errorTimes) >= 20 {
			break
		}
		var is404Page = false

		ch <- struct{}{}
		//log.Println(u, " ", payload)
		endP := u[len(u)-1:] == "/"
		wg.Add(1)
		go func(payload string) {
			defer func() {
				wg.Done() // 控制所有线程结束
				<-ch      // 并发控制
			}()
			for {
				select {
				case _, ok := <-CloseAll: // 00-捕获所有线程关闭信号，并退出，close for all
					if false == ok {
						atomic.AddInt32(&errorTimes, 21)
					}
					return
				default:
					// 01-异常>20关闭所有fuzz
					if atomic.LoadInt32(&errorTimes) >= 20 {
						pkg.CloseChan(CloseAll)
						return
					}
					// 修复url，默认 认为 payload 不包含/
					szUrl := u + payload
					if strings.HasPrefix(payload, "/") && endP {
						szUrl = u + payload[1:]
					}
					if fuzzPage, req, err := reqPage(szUrl); err == nil && 0 < len(req.Body) {
						// 02-状态码和req1相同，且与req1相似度>9.5，关闭所有fuzz
						fXsd := strsim.Compare(url404req.Body, req.Body)
						bBig95 := 9.5 < fXsd
						if url404.StatusCode == fuzzPage.StatusCode && bBig95 {
							pkg.CloseChan(CloseAll)
							atomic.AddInt32(&errorTimes, 21)
							return
						}
						// 03-异常页面（>400），或相似度与404匹配
						if fuzzPage.StatusCode > 400 || bBig95 {
							// 03.01-异常页面指纹匹配
							technologies = Addfingerprints404(technologies, req, fuzzPage) //基于404页面文件扫描指纹添加
							// 03.02-与绝对404相似度低于0.8，添加body 404 body list
							// 03.03-添加404titlelist
							if 0.8 > fXsd {
								go StudyErrPageAI(req, fuzzPage) // 异常页面学习
							}
						}
						var path1, technologies1 = []string{}, []string{}
						// 04-403： 403 by pass
						if fuzzPage.is403 {
							a11 := ByPass403(&u, &payload, &wg)
							// 表示 ByPass403 成功了, 结果、控制台输出点什么？
							if 0 < len(a11) {
								path1 = append(path1, a11...)
							}
						}
						// 05-跳转检测
						if CheckDirckt(fuzzPage, req) {
							return
						}
						is404Page = CheckIsErrPageAI(req, fuzzPage)
						// 06-成功页面, 非异常页面
						if !is404Page {
							// 1、指纹匹配
							technologies1 = Addfingerprintsnormal(payload, technologies1, req, fuzzPage) // 基于200页面文件扫描指纹添加
							// 2、成功fuzz路径结果添加
							path1 = append(path1, *fuzzPage.Url)
						}
						if 0 < len(path1) {
							async_data <- path1
						}
						if 0 < len(technologies1) {
							async_technologies <- technologies1
						}
					} else { // 这里应该元子操作
						atomic.AddInt32(&errorTimes, 1)
					}
					return
				}
			}
		}(payload)
	}
	// 默认情况等待所有结束
	wg.Wait()
	return path, technologies
}

// html跳转
var reg1 = regexp.MustCompile("(?i)<meta.*http-equiv\\s*=\\s*\"refresh\".*content\\s*=\\s*\"5;\\s*url=")

// js跳转
var reg2 = regexp.MustCompile("(window|self|top)\\.location\\.href\\s*=")

// 跳转检测
//  1、状态码跳转：301 代表永久性转移(Permanently Moved)；302 redirect: 302 代表暂时性转移(Temporarily Moved )
//  2、html刷新跳转
//  3、js 跳转
func CheckDirckt(fuzzPage *Page, req *pkg.Response) bool {
	if nil == fuzzPage || nil == req {
		return false
	}
	data := []byte(req.Body)
	// 01 redirect:
	if 302 == req.StatusCode || 301 == req.StatusCode {
		return true
	} else if 0 < len(data) && (0 < len(reg1.Find(data)) || 0 < len(reg2.Find(data))) { // html刷新跳转;js 跳转
		return true
	}
	return false
}
