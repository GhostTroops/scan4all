package pkg

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

type Response struct {
	Status        string
	StatusCode    int
	Body          string
	Header        http.Header
	ContentLength int64
	RequestUrl    string
}

var HttpProxy string

func HttpRequsetBasic(username string, password string, urlstring string, toupper string, postdate string, isredirect bool, headers map[string]string) (*Response, error) {
	var tr *http.Transport
	if HttpProxy != "" {
		uri, _ := url.Parse(HttpProxy)
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
	if isredirect {
		jar, _ := cookiejar.New(nil)
		client = &http.Client{
			Timeout:   time.Duration(10) * time.Second,
			Transport: tr,
			Jar:       jar,
		}
	}
	req, err := http.NewRequest(strings.ToUpper(toupper), urlstring, strings.NewReader(postdate))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	for v, k := range headers {
		req.Header[v] = []string{k}
	}
	resp, err := client.Do(req)
	if err == nil {
		body, err2 := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
		if err2 == nil {
			return &Response{resp.Status, resp.StatusCode, string(body), resp.Header, resp.ContentLength, resp.Request.URL.String()}, err2
		}
	}
	return nil, err
}

func HttpRequset(urlstring string, toupper string, postdate string, isredirect bool, headers map[string]string) (*Response, error) {
	var tr *http.Transport
	if HttpProxy != "" {
		uri, _ := url.Parse(HttpProxy)
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
	if isredirect {
		jar, _ := cookiejar.New(nil)
		client = &http.Client{
			Timeout:   time.Duration(10) * time.Second,
			Transport: tr,
			Jar:       jar,
		}
	}
	req, err := http.NewRequest(strings.ToUpper(toupper), urlstring, strings.NewReader(postdate))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	for v, k := range headers {
		req.Header[v] = []string{k}
	}
	resp, err := client.Do(req)
	if err == nil {
		body, err2 := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
		if err2 == nil {
			return &Response{resp.Status, resp.StatusCode, string(body), resp.Header, resp.ContentLength, resp.Request.URL.String()}, err2
		}
	}
	return nil, err
}
