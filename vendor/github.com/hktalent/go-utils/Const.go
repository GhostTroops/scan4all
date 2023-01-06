package go_utils

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
)

// 这涉及一个扫描任务的状态，会表示为若干中状态
// 一旦定义， 产生数据后，绝不能在中间加类型，只能在最后加类型
const (
	ScanType_SSLInfo         = uint64(1 << iota) // 01- SSL信息分析，并对域名信息进行收集、进入下一步流程
	ScanType_SubDomain                           // 02- 子域名爆破，新域名回归 到:  1 <-- -> 2，做去重处理
	ScanType_MergeIps                            // 03- 默认自动合并ip，记录ip与域名的关联关系，再发送payload时考虑：相同ip不同域名，相同payload分别发送 合并相同目标 若干域名的ip，避免扫描时重复
	ScanType_WeakPassword                        // 04- 密码破解，隐含包含了: 端口扫描(05-masscan + 06-nmap)
	ScanType_Masscan                             // 05- 合并后的ip 进行快速端口扫描
	ScanType_Nmap                                // 06、精准 端口指纹，排除masscan已经识别的几种指纹
	ScanType_IpInfo                              // 07- 获取ip info
	ScanType_GoPoc                               // 08- go-poc 检测, 隐含包含了: 端口扫描(05-masscan + 06-nmap)
	ScanType_PortsWeb                            // 09- web端口识别，Naabu,识别 https，识别存活的web端口，再进入下一流程
	ScanType_WebFingerprints                     // 10- web指纹，识别蜜罐，并标识
	ScanType_WebDetectWaf                        // 11- detect WAF
	ScanType_WebScrapy                           // 12- 爬虫分析，form表单识别，字段名识别，form action提取；
	ScanType_WebInfo                             // 13- server、x-powerby、x***，url、ip、其他敏感信息（姓名、电话、地址、身份证）
	ScanType_WebVulsScan                         // 14- 包含 nuclei
	ScanType_WebDirScan                          // 14- dir爆破,Gobuster
	ScanType_Naabu                               // 15- naabu
	ScanType_Httpx                               // 16- httpx
	ScanType_DNSx                                // 17- DNSX
	ScanType_SaveEs                              // 18- Save Es
	ScanType_Jaeles                              // 19 - jaeles
	ScanType_Uncover                             // Uncover
	ScanType_Ffuf                                // ffuf
	ScanType_Amass                               // amass
	ScanType_Subfinder                           // subfinder
	ScanType_Shuffledns                          // shuffledns
	ScanType_Tlsx                                // tlsx
	ScanType_Katana                              // katana
	ScanType_Nuclei                              // nuclei
	ScanType_Gobuster                            // Gobuster
)
const (
	ScanType_Ips = ScanType_SSLInfo | ScanType_Tlsx | ScanType_Masscan | ScanType_Nmap | ScanType_IpInfo|ScanType_Uncover|ScanType_GoPoc
	ScanType_Webs = ScanType_SSLInfo | ScanType_Tlsx | ScanType_GoPoc|ScanType_WebFingerprints|ScanType_WebDetectWaf|ScanType_WebVulsScan|ScanType_Nuclei|ScanType_Gobuster|ScanType_Uncover|ScanType_Httpx|ScanType_WebDirScan
)


// 全局线程控制
var Wg *sync.WaitGroup = &sync.WaitGroup{}

// 全局控制
var RootContext = context.Background()

// 全局关闭所有线程
var Ctx_global, StopAll = context.WithCancel(RootContext)

// 多次使用，一次性编译效率更高
var DeleteMe = regexp.MustCompile("rememberMe=deleteMe")

// 自定义http 头
var CustomHeaders []string

/*
X-Forwarded-Host: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Host: 127.0.0.1
*/
// 获取 自定义头信息等raw模式
func GetCustomHeadersRaw() string {
	if 0 < len(CustomHeaders) {
		return "\r\n" + strings.Join(CustomHeaders, "\r\n")
	}
	return ""
}

// 全局设置header
func SetHeader(m *http.Header) {
	if 0 < len(CustomHeaders) && nil != m {
		for _, i := range CustomHeaders {
			n := strings.Index(i, ":")
			m.Set(strings.TrimSpace(i[:n]), strings.TrimSpace(i[n+1:]))
		}
	}
}

// 设置map格式的header
func SetHeader4Map(m *map[string]string) {
	if 0 < len(CustomHeaders) && nil != m {
		for _, i := range CustomHeaders {
			n := strings.Index(i, ":")
			(*m)[strings.TrimSpace(i[:n])] = strings.TrimSpace(i[n+1:])
		}
	}
}

// 异步执行方法，只适合无返回值、或使用管道返回值的方法
// 程序main整体等待
func DoSyncFunc(cbk func()) {
	Wg.Add(1)
	go func() {
		defer Wg.Done()
		for {
			select {
			case <-Ctx_global.Done():
				fmt.Println("接收到全局退出事件")
				return
			default:
				cbk()
				return
			}
		}
	}()
}

// 检查 cookie
// Shiro CVE_2016_4437 cookie
// 其他POC cookie同一检查入口
func CheckShiroCookie(header *http.Header) int {
	var SetCookieAll string
	if nil != header {
		//if hd, ok := header["Set-Cookie"]; ok {
		for i := range (*header)["Set-Cookie"] {
			SetCookieAll += (*header)["Set-Cookie"][i]
		}
		return len(DeleteMe.FindAllStringIndex(SetCookieAll, -1))
	}
	return 0
}

// 匹配响应中 www-Authenticate 是否有认证要求都信息
var BaseReg = regexp.MustCompile("(?i)Basic\\s*realm\\s*=\\s*")

// 管道通讯使用
type PocCheck struct {
	Wappalyzertechnologies *[]string
	URL                    string
	FinalURL               string
	Checklog4j             bool
}

// go POC 检测管道，避免循环引用
var PocCheck_pipe = make(chan *PocCheck, 64)

// 头信息同一检查，并调用合适到go poc进一步爆破、检测
//
//	1、需要认证
//	2、shiro
func CheckHeader(header *http.Header, szUrl string) {
	DoSyncFunc(func() {
		if nil != header {
			a1 := []string{}
			if v := (*header)["www-Authenticate"]; 0 < len(v) {
				if 0 < len(BaseReg.FindAll([]byte(v[0]), -1)) {
					a1 = append(a1, "basic")
				}
			}
			if 0 < CheckShiroCookie(header) {
				a1 = append(a1, "shiro")
			}
			if 0 < len(a1) && os.Getenv("NoPOC") != "true" {
				PocCheck_pipe <- &PocCheck{Wappalyzertechnologies: &a1, URL: szUrl, FinalURL: szUrl, Checklog4j: false}
			}
		}
	})
}
