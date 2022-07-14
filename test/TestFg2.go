package main

import (
	"crypto/tls"
	"fmt"
	"github.com/hktalent/scan4all/pkg"
	"github.com/hktalent/scan4all/pkg/fingerprint"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

func doUrl(host string) (headers map[string][]string, body []byte, title string, url string, status_code string) {
	timeout := time.Duration(8 * time.Second)
	var tr *http.Transport

	tr = &http.Transport{
		MaxIdleConnsPerHost: -1,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
	}
	client := http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse /* 不进入重定向 */
		},
	}
	resp, err := client.Get(host)
	if err != nil {
		return nil, nil, "", host, ""
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, nil, "", host, ""
		}
		//srcCode := md5.Sum(body)
		//faviconMMH3 := strings.ToLower(fmt.Sprintf("%x", srcCode))
		return resp.Header, body, "", host, fmt.Sprintf("%d", resp.StatusCode)
	} else {
		return nil, nil, "", host, ""
	}
}
func main() {
	a := strings.Split(`http://101.132.254.177:8161
http://101.132.155.38:8161/
http://101.132.34.146:8161`, "\n")
	if nil == pkg.Cache1 {
		pkg.NewKvDbOp()
	}
	fingerprint.New()
	for _, x := range a {
		log.Printf("%+v", fingerprint.FingerScan(doUrl(x)))
	}
}
