package go_utils

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var EnableHoneyportDetection = true

// 内存缓存，避免相同目标多次执行
var hdCache sync.Map

var ipCIDS = regexp.MustCompile("^(\\d+\\.){3}\\d+\\/\\d+$")

//  检查 蜜罐 Server信息，check Honeypor server info
func CheckHoneyportDetection4HeaderServer(server, szUrl string) bool {
	if 50 < len(server) || 3 < len(strings.Split(server, ",")) {
		hdCache.Store(szUrl, true)
		SendLog(szUrl, string(Scan4all), "Honeypot found", "")
		return true
	}
	return false
}

// 添加蜜罐检测，并自动跳过目标，默认false跳过蜜罐检测
// 考虑内存缓存结果
func HoneyportDetection(host string) bool {
	host = strings.TrimSpace(host)
	if !EnableHoneyportDetection || 5 > len(host) || ipCIDS.MatchString(host) {
		return false
	}
	if "http" != strings.ToLower(host[0:4]) {
		host = "http://" + host
	}
	oUrl, err := url.Parse(strings.TrimSpace(host))
	if err != err {
		return false
	}
	szK := oUrl.Scheme + "//" + oUrl.Hostname()

	if v, ok := hdCache.Load(szK); ok {
		return v.(bool)
	}
	if nil == err {
		timeout := time.Duration(8 * time.Second)
		var tr *http.Transport

		tr = &http.Transport{
			MaxIdleConnsPerHost: -1,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:   true,
		}
		client := http.Client{
			Timeout:   timeout,
			Transport: tr,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse /* 不进入重定向 */
			},
		}
		resp, err := client.Head(szK)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				if a, ok := resp.Header["Server"]; ok {
					if CheckHoneyportDetection4HeaderServer(a[0], szK) {
						return true
					}
				}
			}
		}
	}
	hdCache.Store(szK, false)

	return false
}
