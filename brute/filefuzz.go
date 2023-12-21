package brute

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/goSqlite_gorm/lib/scan/Const"
	"github.com/GhostTroops/scan4all/lib/goSqlite_gorm/pkg/models"
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/GhostTroops/scan4all/pkg/fingerprint"
	"github.com/antlabs/strsim"
	"log"
	"mime"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 备份、敏感文件后缀
//
//go:embed dicts/bakSuffix.txt
var bakSuffix string

// 备份、敏感文件 http头类型 ContentType 检测
//
//go:embed dicts/fuzzContentType1.txt
var fuzzct string

// 敏感文件前缀
//
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
	disabledFileFuzz = !util.GetValAsBool("enableFileFuzz")
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
	header["upgrade-insecure-requests"] = "1"
	//header["Connection"] = "close"
	//header["Pragma"] = "no-cache"
	// by WAF
	header = *ByWafHd(&header)

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
//
//	检测头信息是否有敏感文件、本份文件、流文件等敏感信息
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
	regsMap          = make(map[string]*regexp.Regexp) // fuzz 正则库
	disabledFileFuzz = false                           // 是否开启fuzz
	NoDoPath         sync.Map
	NoDoPathInit     = false
)

func DoInitMap() {
	if NoDoPathInit == false && "" != fingerprint.FgDictFile {
		NoDoPathInit = true
		if data, err := os.ReadFile(fingerprint.FgDictFile); nil == err {
			a := strings.Split(strings.TrimSpace(string(data)), "\n")
			for _, k := range a {
				NoDoPath.Store(k, true)
			}
		}
	}
}

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
		// 基于工厂方法构建
		util.EngineFuncFactory(Const.ScanType_WebDirScan, func(evt *models.EventData, args ...interface{}) {
			filePaths, fileFuzzTechnologies := FileFuzz(evt.Task.ScanWeb, 200, 100, "")
			util.SendEngineLog(evt, Const.ScanType_WebDirScan, filePaths, fileFuzzTechnologies)
		})

		// 注册一个
	})
}

// 绝对404请求文件前缀
//var file_not_support = "file_not_support"

// 绝对404请求文件
//var RandStr = file_not_support + "_scan4all"

// 随机10个字符串
var RandStr4Cookie = util.RandStringRunes(10)

type FuzzData struct {
	Path *[]string
	Req  *util.Page
}

// https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types
var (
	r001 = regexp.MustCompile(`\.(aac)|(abw)|(arc)|(avif)|(avi)|(azw)|(bin)|(bmp)|(bz)|(bz2)|(cda)|(csh)|(css)|(csv)|(doc)|(docx)|(eot)|(epub)|(gz)|(gif)|(ico)|(ics)|(jar)|(jpeg)|(jpg)|(js)|(json)|(jsonld)|(mid)|(midi)|(mjs)|(mp3)|(mp4)|(mpeg)|(mpkg)|(odp)|(ods)|(odt)|(oga)|(ogv)|(ogx)|(opus)|(otf)|(png)|(pdf)|(php)|(ppt)|(pptx)|(rar)|(rtf)|(sh)|(svg)|(tar)|(tif)|(tiff)|(ts)|(ttf)|(txt)|(vsd)|(wav)|(weba)|(webm)|(webp)|(woff)|(woff2)|(xhtml)|(xls)|(xlsx)|(xml)|(xul)|(zip)|(3gp)|(3g2)|(7z)$`)
	cT1  = make(chan struct{}, 1) // 每次只允许1个url fuzz
)

// 重写了fuzz：优化流程、优化算法、修复线程安全bug、增加智能功能
//
//	两次  ioutil.ReadAll(resp.Body)，第二次就会 Read返回EOF error
//	去除指纹请求的路径，避免重复
func FileFuzz(u string, indexStatusCode int, indexContentLength int, indexbody string) ([]string, []string) {
	if util.TestRepeat(u) {
		return []string{}, []string{}
	}
	cT1 <- struct{}{}
	defer func() {
		<-cT1
	}()
	if disabledFileFuzz {
		return []string{}, []string{}
	}
	DoInitMap()
	u01, err := url.Parse(strings.TrimSpace(u))
	if nil == err {
		u = u01.Scheme + "://" + u01.Host + "/"
	}
	// 用host，确保https、http只走一种协议即可
	if disabledFileFuzz || util.TestRepeat(u01.Host, "FileFuzz") {
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
	if err == nil && ok && nil != url404req {
		// 升级协议
		if "" != url404req.Protocol && !strings.Contains(url404req.Protocol, "HTTP/1.") {
			u = "https://" + u01.Host + "/"
		}
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
	// 终止fuzz任务
	ctx, stop := context.WithCancel(util.Ctx_global)
	// 终止 接收结果任务
	ctx2, stop2 := context.WithCancel(util.Ctx_global)
	// 控制 fuzz 线程数
	var ch = make(chan struct{}, util.Fuzzthreads)
	// 异步接收结果
	var async_data = make(chan *FuzzData, util.Fuzzthreads*2)
	var async_technologies = make(chan []string, util.Fuzzthreads*2)
	// 字典长度的 30% 的错误
	var MaxErrorTimes int32 = int32(util.GetValAsInt("MaxErrorTimes", 50)) //int32(float32(len(filedic)) * 0.005)
	if strings.HasPrefix(url404req.Protocol, "HTTP/2") || strings.HasPrefix(url404req.Protocol, "HTTP/3") {
		MaxErrorTimes = int32(len(filedic))
	}
	//var MaxErrorTimes int32 = 100
	if c1 := util.GetClient(u, map[string]interface{}{"Timeout": 15 * time.Second, "ErrLimit": MaxErrorTimes}); nil != c1 {
		util.PutClientCc(u, c1)
	}
	//defer func() {
	//	close(ch)
	//	close(async_data)
	//	close(async_technologies)
	//}()
	//log.Printf("start fuzz: %s for", u)
	nStop := 400
	var lst200 *util.Response
	t001 := time.NewTicker(3 * time.Second)
	var nCnt int32 = 0
	// 异步 接收 fuzz 结果
	go func() {
		defer stop()
		for {
			select {
			case <-ctx2.Done():
				return
			case <-t001.C:
				fmt.Printf("file fuzz(ok/total:%5d/%5d) (errs/limitErr:%3d/%3d) %s\r", nCnt, len(filedic), errorTimes, MaxErrorTimes, u)
				if errorTimes >= MaxErrorTimes {
					stop()
				}
			case x1, ok := <-async_data:
				if ok {
					if lst200 == nil || x1.Req.Resqonse.Body != lst200.Body {
						path = append(path, (*x1.Path)...)
					}
					lst200 = x1.Req.Resqonse
					if len(path) > nStop {
						stop() //发停止指令
						atomic.AddInt32(&errorTimes, MaxErrorTimes)
						return
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
				// <-time.After(time.Duration(100) * time.Millisecond)
			}
		}
	}()
	log.Printf("wait for file fuzz(dicts:%d) %s \r", len(filedic), u)

BreakAll:
	for _, payload := range filedic {
		payload = strings.TrimSpace(payload)
		// httpx 跑过的这里不再重复跑
		if _, ok := NoDoPath.Load(payload); ok {
			continue
		}
		// 接收到停止信号
		if errorTimes >= MaxErrorTimes {
			stop()
			break
		}
		select {
		case <-ctx.Done():
			break BreakAll
		default:
			{
				endP := u[len(u)-1:] == "/"
				ch <- struct{}{}
				wg.Add(1)
				go func(payload string) {
					payload = strings.TrimSpace(payload)
					defer func() {
						<-ch // 并发控制
						wg.Done()
					}()
					atomic.AddInt32(&nCnt, 1)
					select {
					case <-ctx.Done(): // 00-捕获所有线程关闭信号，并退出，close for all
						atomic.AddInt32(&errorTimes, MaxErrorTimes)
						return
					default:
						//if _, ok := noRpt.Load(szKey001Over); ok {
						//	stop()
						//	return
						//}
						// 01-异常>20关闭所有fuzz
						if errorTimes >= MaxErrorTimes {
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
							if 200 == req.StatusCode {
								if nil == lst200 {
									lst200 = req
								} else if lst200.Body == req.Body { // 无意义的 200
									return
								}
								if oU1, err := url.Parse(szUrl); nil == err {
									a50 := r001.FindStringSubmatch(oU1.Path)
									if 0 < len(a50) {
										s2 := mime.TypeByExtension(filepath.Ext(a50[0]))
										ct := (*req).Header.Get("Content-Type")
										if "" != ct && "" != s2 && strings.Contains(ct, s2) {
											return
										}
									}
								}
								//log.Printf("%d : %s \n", req.StatusCode, szUrl)
								if IsLoginPage(szUrl, req.Body, req.StatusCode) {
									technologies = append(technologies, "loginpage")
								}
							}
							go util.CheckHeader(req.Header, u)
							// 02-状态码和req1相同，且与req1相似度>9.5，关闭所有fuzz
							fXsd := strsim.Compare(url404req.Body, req.Body)
							bBig95 := 0.95 < fXsd
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
										async_data <- &FuzzData{Path: &a11, Req: fuzzPage}
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
								async_data <- &FuzzData{Path: &path1, Req: fuzzPage}
							}
							if 0 < len(technologies1) {
								async_technologies <- technologies1
							}
						} else { // 这里应该元子操作
							if nil != err {
								//if nil != client && strings.Contains(err.Error(), " connect: connection reset by peer") {
								//	client.Client = client.GetClient(nil)
								//}
								//log.Printf("file fuzz %s is err %v\n", szUrl, err)
							}
							atomic.AddInt32(&errorTimes, 1)
						}
						return
					}
				}(payload)
			}
		}
	}
	// 默认情况等待所有结束
	wg.Wait()
	if 0 < len(path) {
		util.SendLog(u, "brute", strings.Join(path, "\n"), "")

		log.Printf("fuzz is over: %s found:\n%s\n", u, strings.Join(path, "\n"))
		path = util.SliceRemoveDuplicates(path)
	}
	technologies = util.SliceRemoveDuplicates(technologies)
	if 0 < len(technologies) {
		util.SendLog(u, "brute", strings.Join(technologies, "\n"), "")
	}

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
//
//	1、状态码跳转：301 代表永久性转移(Permanently Moved)；302 redirect: 302 代表暂时性转移(Temporarily Moved )
//	2、html刷新跳转
//	3、js 跳转
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
