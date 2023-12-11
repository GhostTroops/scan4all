package brute

import (
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/GhostTroops/scan4all/pkg/httpx/common/httpx"
	"net/url"
	"regexp"
	"strings"
)

var clp = regexp.MustCompile(`<link[^>]*href=['"](.*?)['"]`)
var urlReg = regexp.MustCompile(`\/(login|Login)`)
var urlReg1 = regexp.MustCompile(`\.(png|jpg|jpeg|gif|css)$`)
var bdReg = regexp.MustCompile(`(login|Login|type="password"|忘记密码|注册|登录|forget|登录页面)`)

func IsLoginPage(inputurl, body string, StatusCode int) bool {
	if StatusCode == 200 && 0 == len(urlReg1.FindAllString(inputurl, -1)) && 0 < len(urlReg.FindAllString(inputurl, -1)) || 0 < len(bdReg.FindAllString(body, -1)) {
		return true
	}
	return false
}

func CheckLoginPage(inputurl string, resp *httpx.Response) bool {
	if IsLoginPage(inputurl, string(resp.Data), resp.StatusCode) {
		return true
	}
	if req, err := util.HttpRequset(inputurl, "GET", "", true, nil); err == nil {
		if 0 < len(bdReg.FindAllString(req.Body, -1)) {
			return true
		}
		cssurl := clp.FindAllStringSubmatch(req.Body, -1)
		for _, v := range cssurl {
			if strings.Contains(v[1], ".css") {
				u, err := url.Parse(strings.TrimSpace(inputurl))
				if err != nil {
					return false
				}
				href, err := url.Parse(strings.TrimSpace(v[1]))
				if err != nil {
					return false
				}
				if err != nil {
					return false
				}
				// 转换为绝对的可访问的url
				hrefurl := u.ResolveReference(href)
				// 原理，css中包含了login
				if reqcss, err := util.HttpRequset(hrefurl.String(), "GET", "", true, nil); err == nil {
					if util.StrContains(reqcss.Body, "login") {
						return true
					}
				}
			}
		}
		return false
	}
	return false
}
