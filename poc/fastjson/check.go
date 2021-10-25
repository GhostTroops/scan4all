package fastjson

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"net/url"
	"regexp"
	"strings"
)

func Check(u string) string {
	domainx := getinputurl(u)
	for _, jsonurl := range domainx {
		header := make(map[string]string)
		header["Content-Type"] = "application/json;charset=UTF-8"
		if req, err := pkg.HttpRequset(jsonurl, "POST", `{"\u0040\u0074\u0079\u0070\u0065": "\u006A\u0061\u0076\u0061\u002E\u006C\u0061\u006E\u0067\u002E\u0041\u0075\u0074\u006F\u0043\u006C\u006F\u0073\u0065\u0061\u0062\u006C\u0065"`, false, header); err == nil {
			fastjsonreg := regexp.MustCompile(`fastjson-version (1\.2\.\d+)`)
			fastjsonversionlilst := fastjsonreg.FindStringSubmatch(req.Body)
			if fastjsonversionlilst != nil {
				pkg.POClog(fmt.Sprintf("Found vuln fastjson version %s|%s\n", fastjsonversionlilst[len(fastjsonversionlilst)-1:][0], u))
				return fastjsonversionlilst[len(fastjsonversionlilst)-1:][0]
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
