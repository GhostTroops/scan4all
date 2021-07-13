package brute

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type userpass struct {
	username string
	password string
}

var (
	tomcatuserpass   = []userpass{{"admin", ""}, {"root", ""}, {"test", "test"}, {"root", "admin"}, {"admin", "admin"}, {"root", "123456"}, {"admin", "123456"}, {"Tomcat-manager", "manager"}, {"admin", "admanager"}, {"admin", "admin"}, {"ADMIN", "ADMIN"}, {"admin", "adrole1"}, {"admin", "adroot"}, {"admin", "ads3cret"}, {"admin", "adtomcat"}, {"admin", "advagrant"}, {"admin", "password"}, {"admin", "password1"}, {"admin", "Password1"}, {"admin", "tomcat"}, {"admin", "vagrant"}, {"both", "admanager"}, {"both", "admin"}, {"both", "adrole1"}, {"both", "adroot"}, {"both", "ads3cret"}, {"both", "adtomcat"}, {"both", "advagrant"}, {"both", "tomcat"}, {"cxsdk", "kdsxc"}, {"j2deployer", "j2deployer"}, {"manager", "admanager"}, {"manager", "admin"}, {"manager", "adrole1"}, {"manager", "adroot"}, {"manager", "ads3cret"}, {"manager", "adtomcat"}, {"manager", "advagrant"}, {"manager", "manager"}, {"ovwebusr", "OvW*busr1"}, {"QCC", "QLogic66"}, {"role1", "admanager"}, {"role1", "admin"}, {"role1", "adrole1"}, {"role1", "adroot"}, {"role1", "ads3cret"}, {"role1", "adtomcat"}, {"role1", "advagrant"}, {"role1", "role1"}, {"role1", "tomcat"}, {"role", "changethis"}, {"root", "admanager"}, {"root", "admin"}, {"root", "adrole1"}, {"root", "adroot"}, {"root", "ads3cret"}, {"root", "adtomcat"}, {"root", "advagrant"}, {"root", "changethis"}, {"root", "owaspbwa"}, {"root", "password"}, {"root", "password1"}, {"root", "Password1"}, {"root", "r00t"}, {"root", "root"}, {"root", "toor"}, {"tomcat", ""}, {"tomcat", "admanager"}, {"tomcat", "admin"}, {"tomcat", "adrole1"}, {"tomcat", "adroot"}, {"tomcat", "ads3cret"}, {"tomcat", "adtomcat"}, {"tomcat", "advagrant"}, {"tomcat", "changethis"}, {"tomcat", "password"}, {"tomcat", "password1"}, {"tomcat", "s3cret"}, {"tomcat", "tomcat"}, {"xampp", "xampp"}, {"server_admin", "owaspbwa"}, {"admin", "owaspbwa"}, {"demo", "demo"}, {"root", "root123"}, {"root", "password"}, {"root", "root@123"}, {"root", "root888"}, {"root", "root"}, {"root", "a123456"}, {"root", "123456a"}, {"root", "5201314"}, {"root", "111111"}, {"root", "woaini1314"}, {"root", "qq123456"}, {"root", "123123"}, {"root", "000000"}, {"root", "1qaz2wsx"}, {"root", "1q2w3e4r"}, {"root", "qwe123"}, {"root", "7758521"}, {"root", "123qwe"}, {"root", "a123123"}, {"root", "123456aa"}, {"root", "woaini520"}, {"root", "woaini"}, {"root", "100200"}, {"root", "1314520"}, {"root", "woaini123"}, {"root", "123321"}, {"root", "q123456"}, {"root", "123456789"}, {"root", "123456789a"}, {"root", "5211314"}, {"root", "asd123"}, {"root", "a123456789"}, {"root", "z123456"}, {"root", "asd123456"}, {"root", "a5201314"}, {"root", "aa123456"}, {"root", "zhang123"}, {"root", "aptx4869"}, {"root", "123123a"}, {"root", "1q2w3e4r5t"}, {"root", "1qazxsw2"}, {"root", "5201314a"}, {"root", "1q2w3e"}, {"root", "aini1314"}, {"root", "31415926"}, {"root", "q1w2e3r4"}, {"root", "123456qq"}, {"root", "woaini521"}, {"root", "1234qwer"}, {"root", "a111111"}, {"root", "520520"}, {"root", "iloveyou"}, {"root", "abc123"}, {"root", "110110"}, {"root", "111111a"}, {"root", "123456abc"}, {"root", "w123456"}, {"root", "7758258"}, {"root", "123qweasd"}, {"root", "159753"}, {"root", "qwer1234"}, {"root", "a000000"}, {"root", "qq123123"}, {"root", "zxc123"}, {"root", "123654"}, {"root", "abc123456"}, {"root", "123456q"}, {"root", "qq5201314"}, {"root", "12345678"}, {"root", "000000a"}, {"root", "456852"}, {"root", "as123456"}, {"root", "1314521"}, {"root", "112233"}, {"root", "521521"}, {"root", "qazwsx123"}, {"root", "zxc123456"}, {"root", "abcd1234"}, {"root", "asdasd"}, {"root", "666666"}, {"root", "love1314"}, {"root", "QAZ123"}, {"root", "aaa123"}, {"root", "q1w2e3"}, {"root", "aaaaaa"}, {"root", "a123321"}, {"root", "123000"}, {"root", "11111111"}, {"root", "12qwaszx"}, {"root", "5845201314"}, {"root", "s123456"}, {"root", "nihao123"}, {"root", "caonima123"}, {"root", "zxcvbnm123"}, {"root", "wang123"}, {"root", "159357"}, {"root", "1A2B3C4D"}, {"root", "asdasd123"}, {"root", "584520"}, {"root", "753951"}, {"root", "147258"}, {"root", "1123581321"}, {"root", "110120"}, {"root", "qq1314520"}, {"admin", "admin123"}, {"admin", "password"}, {"admin", "admin@123"}, {"admin", "admin888"}, {"admin", "root"}, {"admin", "a123456"}, {"admin", "123456a"}, {"admin", "5201314"}, {"admin", "111111"}, {"admin", "woaini1314"}, {"admin", "qq123456"}, {"admin", "123123"}, {"admin", "000000"}, {"admin", "1qaz2wsx"}, {"admin", "1q2w3e4r"}, {"admin", "qwe123"}, {"admin", "7758521"}, {"admin", "123qwe"}, {"admin", "a123123"}, {"admin", "123456aa"}, {"admin", "woaini520"}, {"admin", "woaini"}, {"admin", "100200"}, {"admin", "1314520"}, {"admin", "woaini123"}, {"admin", "123321"}, {"admin", "q123456"}, {"admin", "123456789"}, {"admin", "123456789a"}, {"admin", "5211314"}, {"admin", "asd123"}, {"admin", "a123456789"}, {"admin", "z123456"}, {"admin", "asd123456"}, {"admin", "a5201314"}, {"admin", "aa123456"}, {"admin", "zhang123"}, {"admin", "aptx4869"}, {"admin", "123123a"}, {"admin", "1q2w3e4r5t"}, {"admin", "1qazxsw2"}, {"admin", "5201314a"}, {"admin", "1q2w3e"}, {"admin", "aini1314"}, {"admin", "31415926"}, {"admin", "q1w2e3r4"}, {"admin", "123456qq"}, {"admin", "woaini521"}, {"admin", "1234qwer"}, {"admin", "a111111"}, {"admin", "520520"}, {"admin", "iloveyou"}, {"admin", "abc123"}, {"admin", "110110"}, {"admin", "111111a"}, {"admin", "123456abc"}, {"admin", "w123456"}, {"admin", "7758258"}, {"admin", "123qweasd"}, {"admin", "159753"}, {"admin", "qwer1234"}, {"admin", "a000000"}, {"admin", "qq123123"}, {"admin", "zxc123"}, {"admin", "123654"}, {"admin", "abc123456"}, {"admin", "123456q"}, {"admin", "qq5201314"}, {"admin", "12345678"}, {"admin", "000000a"}, {"admin", "456852"}, {"admin", "as123456"}, {"admin", "1314521"}, {"admin", "112233"}, {"admin", "521521"}, {"admin", "qazwsx123"}, {"admin", "zxc123456"}, {"admin", "abcd1234"}, {"admin", "asdasd"}, {"admin", "666666"}, {"admin", "love1314"}, {"admin", "QAZ123"}, {"admin", "aaa123"}, {"admin", "q1w2e3"}, {"admin", "aaaaaa"}, {"admin", "a123321"}, {"admin", "123000"}, {"admin", "11111111"}, {"admin", "12qwaszx"}, {"admin", "5845201314"}, {"admin", "s123456"}, {"admin", "nihao123"}, {"admin", "caonima123"}, {"admin", "zxcvbnm123"}, {"admin", "wang123"}, {"admin", "159357"}, {"admin", "1A2B3C4D"}, {"admin", "asdasd123"}, {"admin", "584520"}, {"admin", "753951"}, {"admin", "147258"}, {"admin", "1123581321"}, {"admin", "110120"}, {"admin", "qq1314520"}}
	usernames        = []string{"admin", "test"}
	top100pass       = []string{"admin", "test", "admin123", "password", "admin@123", "admin888", "root", "123456", "a123456", "123456a", "5201314", "111111", "woaini1314", "qq123456", "123123", "000000", "1qaz2wsx", "1q2w3e4r", "qwe123", "7758521", "123qwe", "a123123", "123456aa", "woaini520", "woaini", "100200", "1314520", "woaini123", "123321", "q123456", "123456789", "123456789a", "5211314", "asd123", "a123456789", "z123456", "asd123456", "a5201314", "aa123456", "zhang123", "aptx4869", "123123a", "1q2w3e4r5t", "1qazxsw2", "5201314a", "1q2w3e", "aini1314", "31415926", "q1w2e3r4", "123456qq", "woaini521", "1234qwer", "a111111", "520520", "iloveyou", "abc123", "110110", "111111a", "123456abc", "w123456", "7758258", "123qweasd", "159753", "qwer1234", "a000000", "qq123123", "zxc123", "123654", "abc123456", "123456q", "qq5201314", "12345678", "000000a", "456852", "as123456", "1314521", "112233", "521521", "qazwsx123", "zxc123456", "abcd1234", "asdasd", "666666", "love1314", "QAZ123", "aaa123", "q1w2e3", "aaaaaa", "a123321", "123000", "11111111", "12qwaszx", "5845201314", "s123456", "nihao123", "caonima123", "zxcvbnm123", "wang123", "159357", "1A2B3C4D", "asdasd123", "584520", "753951", "147258", "1123581321", "110120", "qq1314520", "'or'='or'"}
	weblogicuserpass = []userpass{{"weblogic", "weblogic"}, {"weblogic", "welcome1"}, {"weblogic", "Oracle@123"}, {"weblogic", "123456"}, {"weblogic", "weblogic123"}}
	filedic          = []string{"/env", "/actuator", "/actuator/env", "/config", "/config.js", "/console/", "/druid/index.html", "/env.json", "/.env", "/api/swagger-ui.html", "/api/v2/api-docs", "/api/v1/api-docs", "/swagger-resources", "/swagger-ui.html", "/swagger-ui/index.html", "/swagger/docs/v1", "/swagger/docs/v2", "/swagger/ui/index", "/test", "/test.aspx", "/test.htm", "/test.html", "/test.js", "/test.jsp", "/test.log", "/test.php", "/upload", "/api/upload", "/upload/", "/upload.do", "/upload.html", "/upload.php", "/upload.jsp", "/upload.aspx", "/zabbix/", "/grafana/", "/zentao/", "/seeyon/", "/.git/config", "/.svn/entries", "/phpinfo.php", "/www.zip", "/www.rar", "/www.7z", "/www.tar.gz", "/www.tar", "/web.zip", "/web.rar", "/web.7z", "/web.tar.gz", "/web.tar", "/wwwroot.zip", "/wwwroot.rar", "/wwwroot.7z", "/wwwroot.tar.gz", "/wwwroot.tar", "/data.zip", "/data.rar", "/data.7z", "/data.tar.gz", "/data.tar", "/网站备份.rar", "/网站备份.zip", "/phpmyadmin/index.php", "/phpMyAdmin/index.php", "/Runtime/Logs/"}
	HttpProxy        string
)

func httpRequsetBasic(username string, password string, urlstring string, toupper string, postdate string) (*http.Response, error) {
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
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	req, err := http.NewRequest(strings.ToUpper(toupper), urlstring, strings.NewReader(postdate))
	if err != nil {
		fmt.Println(err)
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
	}
	return resp, err
}

func httpRequset(urlstring string, toupper string, postdate string) (*http.Response, error) {
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
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	req, err := http.NewRequest(strings.ToUpper(toupper), urlstring, strings.NewReader(postdate))
	if err != nil {
		fmt.Println(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
	}
	return resp, err
}
