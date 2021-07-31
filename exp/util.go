package exp

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var HttpProxy string

func HttpRequsetBasic(username string, password string, urlstring string, toupper string, postdate string) (*http.Response, error) {
	var tr *http.Transport
	if HttpProxy != "" {
		uri, _ := url.Parse(HttpProxy)
		tr = &http.Transport{
			MaxIdleConnsPerHost: -1,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DisableKeepAlives: true,
			Proxy:             http.ProxyURL(uri),
		}
	} else {
		tr = &http.Transport{
			MaxIdleConnsPerHost: -1,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DisableKeepAlives: true,
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
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
	}
	return resp, err
}

func HttpRequset(urlstring string, toupper string, postdate string) (*http.Response, error) {
	var tr *http.Transport
	if HttpProxy != "" {
		uri, _ := url.Parse(HttpProxy)
		tr = &http.Transport{
			MaxIdleConnsPerHost: -1,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DisableKeepAlives: true,
			Proxy:             http.ProxyURL(uri),
		}
	} else {
		tr = &http.Transport{
			MaxIdleConnsPerHost: -1,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DisableKeepAlives: true,
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
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
	}
	return resp, err
}
