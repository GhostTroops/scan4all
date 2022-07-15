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
	a := strings.Split(``, "\n")
	if nil == pkg.Cache1 {
		pkg.NewKvDbOp()
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
				xx1 := fingerprint.FingerScan(headers, body, title, url2, status_code)
				if 0 < len(xx1) {
					log.Printf("%s 指纹 %+v", url1, xx1)
				}
			}(x + y)

			//headers, body, title, url, status_code, err := doUrl(x + y)
			//if err != nil {
			//	log.Println(x+y, " error: ", err)
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
