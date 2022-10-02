package go_utils

import (
	"net/http"
	"regexp"
	"strings"
)

// 提取供应链信息
var SupplyChainReg *regexp.Regexp

var UrlMt []*regexp.Regexp = []*regexp.Regexp{
	regexp.MustCompile("^http[s]:\\/\\/[^\\/]+\\/?$"),
	regexp.MustCompile("^http[s]:\\/\\/[^\\/]+\\/[^\\/]+$")}

// url上下文识别、处理
// 确保每个url上下文只计算一次开发商信息
func isCheck(szUrl string) bool {
	for _, x := range UrlMt {
		if x.MatchString(szUrl) {
			return true
		}
	}
	return false
}

// body中开发商信息提取
func DoBody(szUrl, szBody string, head *http.Header) {
	if ok := head.Get("Content-Type"); -1 < strings.Index(ok, "text/html") {
		a := SupplyChainReg.FindAllString(szBody, -1)
		if 0 < len(a) {
		}
	}
}

// 提取供应链信息
// 相同上下文、成功时只提取一次
// 提取header信息：server、X*，不同上下文提取
func SupplyChain(szUrl, szBody string, head *http.Header) {
	szBody = strings.TrimSpace(szBody)
	if nil == head || "" == szBody || "" == szUrl || !isCheck(szUrl) {
		return
	}
	DoBody(szUrl, szBody, head)
}
