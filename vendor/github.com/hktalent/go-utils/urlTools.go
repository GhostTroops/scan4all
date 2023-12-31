package go_utils

import (
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

var mHttp = regexp.MustCompile(`(http[s]?:\/\/[^; $]+)`)

// 调用浏览器 打开url
func OpenUrl4Browser(s string) {
	var cmd *exec.Cmd
	// macOS
	if runtime.GOOS == "darwin" {
		cmd = exec.Command("open", s)
		//cmd = exec.Command("open", "-a", "Safari", s)
	}
	// Windows
	if runtime.GOOS == "windows" {
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", s)
		//cmd = exec.Command("start", "chrome", s)
	}
	if nil != cmd {
		go cmd.Run()
	}
}

// 获取http 响应头信息，并跟踪进入location跳转
//
//	rmHds 可以设置移除 X-Cache-Hits,X-Cache,Via,Traceparent,Server-Timing,Strict-Transport-Security,Date,Paypal-Debug-Id,Set-Cookie,Etag,Content-Type,X-Timer,Accept-Ranges,Cache-Control,X-Xss-Protection,Vary,content-type,etag,paypal-debug-id,set-cookie,traceparent,X-Content-Type-Options,accept-ranges,via,date,strict-transport-security,x-served-by,x-cache,x-cache-hits,x-timer,server-timing,content-length
func GetUrlInfoWithRm(u, rmHds string) http.Header {
	var oR http.Header
	PipE.ErrCount = 0
	PipE.ErrLimit = 10000
	c1 := PipE.GetClient4Http2()
	PipE.UseHttp2 = true
	c1.CheckRedirect = nil
	PipE.DoGetWithClient4SetHd(c1, u, "GET", nil, func(resp *http.Response, err error, szU string) {
		if nil == err {
			if "" != rmHds {
				for _, x := range strings.Split(rmHds, ",") {
					delete(resp.Header, x)
				}
			}
			oR = resp.Header
			//fmt.Printf("%+v", strings.Join(mHttp.FindAllString(resp.Header.Get("Content-Security-Policy"), -1), "\n"))
			//fmt.Printf("\n\n%+v", resp.Header.Get("Content-Security-Policy"))
		}
	}, func() map[string]string {
		return map[string]string{}
	}, true)
	return oR
}

// 获取http 响应头信息，并跟踪进入location跳转
// 获取url header 信息
// 默认移除 X-Cache-Hits,X-Cache,Via,Traceparent,Server-Timing,Strict-Transport-Security,Date,Paypal-Debug-Id,Set-Cookie,Etag,Content-Type,X-Timer,Accept-Ranges,Cache-Control,X-Xss-Protection,Vary,content-type,etag,paypal-debug-id,set-cookie,traceparent,X-Content-Type-Options,accept-ranges,via,date,strict-transport-security,x-served-by,x-cache,x-cache-hits,x-timer,server-timing,content-length
func GetUrlInfo(u string) http.Header {
	return GetUrlInfoWithRm(u, "X-Cache-Hits,X-Cache,Via,Traceparent,Server-Timing,Strict-Transport-Security,Date,Paypal-Debug-Id,Set-Cookie,Etag,Content-Type,X-Timer,Accept-Ranges,Cache-Control,X-Xss-Protection,Vary,content-type,etag,paypal-debug-id,set-cookie,traceparent,X-Content-Type-Options,accept-ranges,via,date,strict-transport-security,x-served-by,x-cache,x-cache-hits,x-timer,server-timing,content-length")
}
