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
	timeout := time.Duration(4 * time.Second)
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
http://101.132.155.38:8161
http://101.132.34.146:8161
http://47.108.13.164:8080
https://13.251.135.159
http://220.184.147.172:8000
http://223.78.125.18:8086
http://59.46.70.114:8091
http://121.8.249.110:3388
https://116.236.79.37:9100
https://61.240.13.104:444
http://118.195.131.216
http://117.10.171.174:10010
http://81.70.143.198:8081
http://1.119.203.138:8181
http://1.117.5.50
http://103.235.238.253
http://210.12.80.130:8080
http://47.117.44.62:8087
http://47.96.141.190
https://223.111.9.4
https://115.159.88.218
http://46.26.46.13
https://182.92.89.1
https://47.104.237.208`, "\n")
	if nil == pkg.Cache1 {
		pkg.NewKvDbOp()
	}
	fingerprint.New()
	//log.Printf("%+v", fingerprint.FgUrls)
	for _, y := range fingerprint.FgUrls {
		for _, x := range a {
			xx1 := fingerprint.FingerScan(doUrl(x + y))
			if 0 < len(xx1) {
				log.Printf("%s 指纹 %+v", x+y, xx1)
			}
		}
	}
}
