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
