package main

import (
	"crypto/tls"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/GhostTroops/scan4all/pkg/fingerprint"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

func doUrl(host string) (headers map[string][]string, body []byte, title string, url string, status_code string, err error) {
	timeout := time.Duration(15 * time.Second)
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
		return nil, nil, "", host, "", err
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, "", host, "", err
	}
	return resp.Header, body, "", host, fmt.Sprintf("%d", resp.StatusCode), nil
}

func main() {
	os.Setenv("MyDebug", "true")
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
	//a := []string{"http://1.119.203.138:8181/",
	//	"http://1.117.5.50/",
	//	"http://103.235.238.253"}
	if nil == util.Cache1 {
		util.NewKvDbOp()
	}
	fingerprint.New()
	//log.Printf("%+v", fingerprint.FgUrls)
	var wg sync.WaitGroup
	for _, y := range fingerprint.FgUrls {
		for _, x := range a {
			//XX11:
			//	select {
			//	case e1 := <-err1:
			//		log.Println(x+y, " error ", e1)
			//		break XX11
			//	default:
			//		wg.Add(1)
			//		go func(url string) {
			//			defer wg.Done()
			//			xx1 := fingerprint.FingerScan(doUrl(url))
			//			if 0 < len(xx1) {
			//				log.Printf("%s 指纹 %+v", url, xx1)
			//			}
			//		}(x + y)
			//	}
			wg.Add(1)
			go func(url1 string) {
				defer wg.Done()
				headers, body, title, url2, status_code, err := doUrl(url1)
				if err != nil {
					//log.Println(url1, " error: ", err)
					return
				}
				xx1, _ := fingerprint.FingerScan(headers, body, title, url2, status_code)
				if 0 < len(xx1) {
					log.Printf("%s 指纹 %+v  %s", url1, xx1, status_code)
				}
			}(x + y)

			//headers, body, title, url, status_code, err := doUrl(x + y)
			//if err != nil {
			//	//log.Println(x+y, " error: ", err)
			//	continue
			//}
			//xx1 := fingerprint.FingerScan(headers, body, title, url, status_code)
			//if 0 < len(xx1) {
			//	log.Printf("%s 指纹 %+v", x+y, xx1)
			//}
		}
	}
	wg.Wait()
	fingerprint.MFid.Range(func(key interface{}, value interface{}) bool {
		log.Printf("%s %+v", key, value)
		return true
	})
}
