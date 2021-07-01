package admin_brute

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	userAgent   string
	check_url   string
	method      string
	httpProxy   string
	postContent string
	timeout     int
)

func getCommandArgs() {
	userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
	method = "GET"
	postContent = ""
	timeout = 60
	httpProxy = ""
}

func getinput() {
	var tr *http.Transport
	if httpProxy != "" {
		uri, _ := url.Parse(httpProxy)
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyURL(uri),
		}
	} else {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	client := &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: tr,
	}

	req, err := http.NewRequest(strings.ToUpper(method), check_url, strings.NewReader(postContent))
	if err != nil {
		fmt.Println(err)
	}
	//设置请求头
	if strings.ToUpper(method) == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	var username = "username"
	var password = "password"
	var domain = check_url + "/login"
	data, _ := ioutil.ReadAll(resp.Body)
	userreg := regexp.MustCompile(`<input.*name="(name|username|user|user_name)".*>`)
	usernamelist := userreg.FindStringSubmatch(string(data))
	if usernamelist != nil {
		username = usernamelist[len(usernamelist)-1:][0]
	}

	passreg := regexp.MustCompile(`<input.*name="(pass|password|passwd)".*>`)
	passlist := passreg.FindStringSubmatch(string(data))
	if passlist != nil {
		password = passlist[len(passlist)-1:][0]
	}

	domainreg := regexp.MustCompile(`<form.*action="(.*?)"`)
	domainlist := domainreg.FindStringSubmatch(string(data))
	fmt.Println(domainlist)
	if domainlist != nil {
		domainx := domainlist[len(domainlist)-1:][0]
		fmt.Println("yes:" + domainx)
		if strings.Contains(domainx, "http") {
			domain = domainx
		} else if domainx == "" {
			domain = check_url
		} else if domainx[0:1] == "/" {
			u, _ := url.Parse(check_url)
			domain = u.Scheme + "://" + u.Host + domainlist[len(domainlist)-1:][0]
		} else {
			domain = check_url + domainlist[len(domainlist)-1:][0]
		}
	} else {
		domainreg2 := regexp.MustCompile(`url:.*?"(.*?)"`)
		domainlist2 := domainreg2.FindStringSubmatch(string(data))
		if domainlist2 != nil {
			domainx := domainlist2[len(domainlist2)-1:][0]
			if strings.Contains(domainx, "http") {
				domain = domainx
			} else if domainx == "" {
				domain = check_url
			} else if domainx[0:1] == "/" {
				u, _ := url.Parse(check_url)
				domain = u.Scheme + "://" + u.Host + domainlist2[len(domainlist2)-1:][0]
			} else {
				domain = check_url + domainlist2[len(domainlist2)-1:][0]
			}
		}
	}
	fmt.Println(username, password, domain)
}

func httpRequset(RememberMe string) int {
	//设置跳过https证书验证，超时和代理
	var tr *http.Transport
	if httpProxy != "" {
		uri, _ := url.Parse(httpProxy)
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyURL(uri),
		}
	} else {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	client := &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse //不允许跳转
		}}
	req, err := http.NewRequest(strings.ToUpper(method), check_url, strings.NewReader(postContent))
	if err != nil {
		fmt.Println(err)
	}
	//设置请求头
	if strings.ToUpper(method) == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Cookie", "rememberMe="+RememberMe)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	var SetCookieAll string
	for i := range resp.Header["Set-Cookie"] {
		SetCookieAll += resp.Header["Set-Cookie"][i]
	}
	if resp.Header != nil {
		counts := regexp.MustCompile("rememberMe=deleteMe").FindAllStringIndex(SetCookieAll, -1)
		return len(counts)
	}
	return 1
}

func Check(url string) {
	check_url = url
	getinput()
}
