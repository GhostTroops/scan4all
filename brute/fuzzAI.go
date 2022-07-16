package brute

import (
	"github.com/hktalent/scan4all/pkg"
	"regexp"
	"strings"
)

// 智能学习: 非正常页面，并记录到库中永久使用
//  0、识别学习过的url就跳过
//  1、body 学习
//  2、标题 学习
//  3、url 去重记录
func StudyErrPageAI(req *pkg.Response, page *Page) {
	if nil == req || nil == page {
		return
	}

	//// 找到 site 网站 的起点url 页面，通常这里可以尝试做一些安全检测
	//if url404.is302 {
	//	location404 = append(location404, *url404.locationUrl)
	//	// 通常，可能存在XSS，获取状态漏洞
	//	//if strings.HasSuffix(url404.locationUrl, file_not_support) {
	//	//	skip302 = true
	//	//}
	//}
	//if url404req.StatusCode == 200 {
	//	page404Title = append(page404Title, *url404.title)
	//}

}

// 检测是否为异常页面，包括状态码检测
func CheckIsErrPageAI(req *pkg.Response, page *Page) bool {

	return false
}

// 获取标题
func Gettitle(body string) *string {
	title := ""
	domainreg2 := regexp.MustCompile(`(?i)<title>([^<]*)</title>`)
	titlelist := domainreg2.FindStringSubmatch(body)
	if len(titlelist) > 1 {
		title = strings.ToLower(strings.TrimSpace(titlelist[1]))
		return &title
	}
	return &title
}
