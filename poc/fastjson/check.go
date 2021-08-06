package fastjson

import (
	"crypto/tls"
	"fmt"
	"github.com/veo/vscan/poc"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func Check(u string) string {
	domainx := getinputurl(u)
	for _, jsonurl := range domainx {
		if body, err := jsonrequest(jsonurl, "POST", `{"\u0040\u0074\u0079\u0070\u0065": "\u006A\u0061\u0076\u0061\u002E\u006C\u0061\u006E\u0067\u002E\u0041\u0075\u0074\u006F\u0043\u006C\u006F\u0073\u0065\u0061\u0062\u006C\u0065"`); err == nil {
			fastjsonreg := regexp.MustCompile(`fastjson-version (1\.2\.\d+)`)
			fastjsonversionlilst := fastjsonreg.FindStringSubmatch(string(body))
			if fastjsonversionlilst != nil {
				fmt.Printf("fastjson|version %s|%s\n", fastjsonversionlilst[len(fastjsonversionlilst)-1:][0], u)
				return fastjsonversionlilst[len(fastjsonversionlilst)-1:][0]
			}
		}
	}
	return ""
}

func getinputurl(domainurl string) (domainurlx []string) {
	requestdata, err := poc.HttpRequsetredirectbody(domainurl, "GET", "")
	if err != nil {
		return nil
	}
	var loginurl []string
	hrefreg := regexp.MustCompile(`location.href='(.*?)'`)
	hreflist := hrefreg.FindStringSubmatch(string(requestdata))
	if hreflist != nil && hreflist[len(hreflist)-1:][0][0:4] != "http" {
		requestdata, err = poc.HttpRequsetredirectbody(domainurl+"/"+hreflist[len(hreflist)-1:][0], "GET", "")
		if err != nil {
			return nil
		}
	}
	domainreg := regexp.MustCompile(`<form.*?action="(.*?)"`)
	domainlist := domainreg.FindStringSubmatch(string(requestdata))
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
	domainlist2 := domainreg2.FindAllStringSubmatch(string(requestdata), -1)
	if domainlist2 != nil {
		for _, a := range domainlist2 {
			domainx := a[1]
			if strings.Contains(domainx, "http") {
				loginurl = append(loginurl, domainx)
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

func jsonrequest(urlstring string, toupper string, postdate string) ([]byte, error) {
	var tr *http.Transport
	if poc.HttpProxy != "" {
		uri, _ := url.Parse(poc.HttpProxy)
		tr = &http.Transport{
			MaxIdleConnsPerHost: -1,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:   true,
			Proxy:               http.ProxyURL(uri),
		}
	} else {
		tr = &http.Transport{
			MaxIdleConnsPerHost: -1,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:   true,
		}
	}
	client := &http.Client{
		Timeout:   time.Duration(10) * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	req, err := http.NewRequest(strings.ToUpper(toupper), urlstring, strings.NewReader(postdate))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	resp, err := client.Do(req)
	if err == nil {
		body, err2 := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
		if err2 == nil {
			return body, err
		}
	}
	return nil, err
}
