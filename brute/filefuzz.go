package brute

import (
	"context"
	_ "embed"
	"github.com/antlabs/strsim"
	"github.com/hktalent/scan4all/lib/util"
	"log"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 备份、敏感文件后缀
//go:embed dicts/bakSuffix.txt
var bakSuffix string

// 备份、敏感文件 http头类型 ContentType 检测
//go:embed dicts/fuzzContentType1.txt
var fuzzct string

// 敏感文件前缀
//go:embed dicts/prefix.txt
var szPrefix string

var (
	ret            = []string{} // 敏感信息文件字典
	prefix, suffix []string     // 敏感信息字典: 前缀、后缀
)

// 生成敏感信息字典
func InitGeneral() int {
	szPrefix = util.GetVal4File("prefix", szPrefix)
	prefix = strings.Split(strings.TrimSpace(szPrefix), "\n")
	suffix = strings.Split(strings.TrimSpace(bakSuffix), "\n")

	for i := 0; i < len(prefix); i++ {
		for j := 0; j < len(suffix); j++ {
			ret = append(ret, "/"+prefix[i]+suffix[j])
		}
	}
	eableFileFuzz = !util.GetValAsBool("enablFileFuzz")
	return len(ret)
}

// 请求url并返回自定义对象
func reqPage(u string) (*util.Page, *util.Response, error) {
	page := &util.Page{Url: &u}
	var method = "GET"
	for _, ext := range suffix {
		if strings.HasSuffix(u, ext) {
			page.IsBackUpPath = true
			method = "HEAD" // 节约请求时间
		}
	}
	header := make(map[string]string)
	header["Accept"] = "*/*"
	header["Connection"] = "close"
	header["Pragma"] = "no-cache"
	// fuzz check Shiro CVE_2016_4437
	header["Cookie"] = "JSESSIONID=" + RandStr4Cookie + ";rememberMe=123"
	if req, err := util.HttpRequset(u, method, "", false, header); err == nil && nil != req && nil != req.Header {
		//if pkg.IntInSlice(req.StatusCode, []int{301, 302, 307, 308}) {
		// 简单粗暴效率高
		if 300 <= req.StatusCode && req.StatusCode < 400 {
			page.Is302 = true
		}
		page.StatusCode = req.StatusCode
		page.Resqonse = req
		page.Header = req.Header
		page.BodyLen = len(req.Body)
		page.Title = Gettitle(req.Body)
		page.LocationUrl = &req.Location
		//  敏感文件头信息检测
		page.IsBackUpPage = CheckBakPage(req)
		// https://zh.m.wikipedia.org/zh-hans/HTTP_403
		// 403 Forbidden 是HTTP协议中的一个HTTP状态码（Status Code）。403状态码意为服务器成功解析请求但是客户端没有访问该资源的权限
		page.Is403 = req.StatusCode == 403
		return page, req, err
	} else {
		return page, nil, err
	}
}

// 敏感文件头信息检测:
//  检测头信息是否有敏感文件、本份文件、流文件等敏感信息
func CheckBakPage(req *util.Response) bool {
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

// 备份、敏感文件 http头类型 ContentType 检测,正则
var regs []string

var (
	regsMap       = make(map[string]*regexp.Regexp) // fuzz 正则库
	eableFileFuzz = false                           // 是否开启fuzz
)

// 初始化字典、数组等
func init() {
	util.RegInitFunc(func() {
		bakSuffix = util.GetVal4File("bakSuffix", bakSuffix)
		fuzzct = util.GetVal4File("fuzzct", fuzzct)

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
	})
}

// 绝对404请求文件前缀
//var file_not_support = "file_not_support"

// 绝对404请求文件
//var RandStr = file_not_support + "_scan4all"

// 随机10个字符串
var RandStr4Cookie = util.RandStringRunes(10)

// 重写了fuzz：优化流程、优化算法、修复线程安全bug、增加智能功能
func FileFuzz(u string, indexStatusCode int, indexContentLength int, indexbody string) ([]string, []string) {
	u01, err := url.Parse(strings.TrimSpace(u))
	if nil == err {
		u = u01.Scheme + "://" + u01.Host + "/"
	}
	if eableFileFuzz || util.TestRepeat(u, "FileFuzz") {
		return []string{}, []string{}
	}

	//log.Println("start file fuzz", u)
	var (
		//path404               = RandStr // 绝对404页面路径
		errorTimes   int32    = 0 // 错误计数器，> 20则退出fuzz
		technologies []string     // 指纹数据
		path         []string     // 成功页面路径
	)
	url404, url404req, err, ok := util.TestIs404Page(u) //reqPage(u + path404)
	if err == nil && ok {
		go util.CheckHeader(url404req.Header, u)
		// 跳过当前目标所有的fuzz,后续所有的fuzz都无意义了
		if 200 == url404.StatusCode || 301 == url404.StatusCode || 302 == url404.StatusCode {
			return []string{}, []string{}
		}
		// 其实这里无论状态码是什么，都是404
		// 所有异常页面 > 400 > 500都做异常页面fuzz指纹
		// 提高精准度，可以只考虑404
		//if url404req.StatusCode > 400 {
		if url404req.StatusCode == 404 {
			technologies = Addfingerprints404(technologies, url404req, url404) //基于404页面文件扫描指纹添加
			StudyErrPageAI(url404req, url404, "")                              // 异常页面学习
		} else {
			return []string{}, []string{}
		}
	} else {
		return []string{}, []string{}
	}
	var wg sync.WaitGroup
	// 中途控制关闭当前目标所有fuzz
	ctx, stop := context.WithCancel(util.Ctx_global)
	ctx2, stop2 := context.WithCancel(util.Ctx_global)
	// 控制 fuzz 线程数
	var ch = make(chan struct{}, util.Fuzzthreads)
	// 异步接收结果
	var async_data = make(chan []string, util.Fuzzthreads*2)
	var async_technologies = make(chan []string, util.Fuzzthreads*2)
	// 字典长度的 70% 的错误
	var MaxErrorTimes int32 = int32(float32(len(filedic)) * 0.7)
	defer func() {
		close(ch)
		close(async_data)
		close(async_technologies)
	}()
	//log.Printf("start fuzz: %s for", u)
	nStop := 400
	go func() {
		for {
			select {
			case x1, ok := <-async_data:
				if ok {
					path = append(path, x1...)
					if len(path) > nStop {
						stop() //发停止指令
						atomic.AddInt32(&errorTimes, MaxErrorTimes)
					}
				} else {
					return
				}
			case x2, ok := <-async_technologies:
				if ok {
					technologies = append(technologies, x2...)
				} else {
					return
				}
			case <-ctx2.Done():
				return
			default:
				// <-time.After(time.Duration(100) * time.Millisecond)
			}
		}
	}()
	for _, payload := range filedic {
		// 接收到停止信号
		if atomic.LoadInt32(&errorTimes) >= MaxErrorTimes {
			break
		}
		//log.Println(u, " ", payload)
		endP := u[len(u)-1:] == "/"
		ch <- struct{}{}
		wg.Add(1)
		go func(payload string) {
			payload = strings.TrimSpace(payload)
			defer func() {
				wg.Done() // 控制所有线程结束
				<-ch      // 并发控制
			}()
			//log.Printf("start file fuzz %s%s \r", u, payload)
			for {
				select {
				case _, ok := <-ch:
					if !ok {
						stop()
						return
					}
				case <-ctx.Done(): // 00-捕获所有线程关闭信号，并退出，close for all
					atomic.AddInt32(&errorTimes, MaxErrorTimes)
					return
				default:
					//if _, ok := noRpt.Load(szKey001Over); ok {
					//	stop()
					//	return
					//}
					// 01-异常>20关闭所有fuzz
					if atomic.LoadInt32(&errorTimes) >= MaxErrorTimes {
						stop() //发停止指令
						return
					}
					// 修复url，默认 认为 payload 不包含/
					szUrl := u + payload
					if strings.HasPrefix(payload, "/") && endP {
						szUrl = u + payload[1:]
					}
					//log.Printf("start fuzz: [%s]", szUrl)
					if fuzzPage, req, err := reqPage(szUrl); err == nil && nil != req && 0 < len(req.Body) {
						//if 200 == req.StatusCode {
						//	log.Printf("%d : %s \n", req.StatusCode, szUrl)
						//}
						go util.CheckHeader(req.Header, u)
						// 02-状态码和req1相同，且与req1相似度>9.5，关闭所有fuzz
						fXsd := strsim.Compare(url404req.Body, req.Body)
						bBig95 := 9.5 < fXsd
						//if "/bea_wls_internal/classes/mejb@/org/omg/stub/javax/management/j2ee/_ManagementHome_Stub.class" == payload {
						//	log.Println("start debug")
						//}
						if url404.StatusCode == fuzzPage.StatusCode && bBig95 {
							stop() //发停止指令
							atomic.AddInt32(&errorTimes, MaxErrorTimes)
							return
						}
						var path1, technologies1 = []string{}, []string{}
						// 03-异常页面（>400），或相似度与404匹配
						if fuzzPage.StatusCode >= 400 || bBig95 || fuzzPage.StatusCode != 200 {
							// 03.01-异常页面指纹匹配
							technologies = Addfingerprints404(technologies, req, fuzzPage) //基于404页面文件扫描指纹添加
							// 03.02-与绝对404相似度低于0.8，添加body 404 body list
							// 03.03-添加404titlelist
							if 0.8 > fXsd && fuzzPage.StatusCode != 200 && fuzzPage.StatusCode != url404.StatusCode {
								StudyErrPageAI(req, fuzzPage, "") // 异常页面学习
							}
							// 04-403： 403 by pass
							if fuzzPage.Is403 && !url404.Is403 {
								a11 := ByPass403(&u, &payload, &wg)
								// 表示 ByPass403 成功了, 结果、控制台输出点什么？
								if 0 < len(a11) {
									async_data <- a11
								}
							}
							return
						}
						// 当前和绝对404不等于404，后续的比较也没有意义了，都等于[200,301,302]都没有意义了，都说明没有fuzz成功
						if url404.StatusCode != 404 && url404.StatusCode == fuzzPage.StatusCode {
							return
						}

						// 05-跳转检测,即便是跳转，如果和绝对404不一样，说明检测成功
						//if CheckDirckt(fuzzPage, req) && url404.StatusCode != fuzzPage.StatusCode {
						//	return
						//}
						// 1、状态码和绝对404一样 2、智能识别算出来
						is404Page := url404.StatusCode == fuzzPage.StatusCode || CheckIsErrPageAI(req, fuzzPage)
						// 06-成功页面, 非异常页面
						if !is404Page || 200 == fuzzPage.StatusCode && url404.StatusCode != fuzzPage.StatusCode {
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
						if nil != err {
							log.Printf("%s is err %v\n", szUrl, err)
						}
						atomic.AddInt32(&errorTimes, 1)
					}
					return
				}
			}
		}(payload)
	}
	// 默认情况等待所有结束
	wg.Wait()
	log.Printf("fuzz is over: %s\n", u)
	technologies = util.SliceRemoveDuplicates(technologies)
	path = util.SliceRemoveDuplicates(path)
	stop() //发停止指令
	<-time.After(time.Second * 2)
	stop2()
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
func CheckDirckt(fuzzPage *util.Page, req *util.Response) bool {
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
