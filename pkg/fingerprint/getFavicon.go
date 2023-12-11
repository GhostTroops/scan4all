package fingerprint

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/GhostTroops/scan4all/pkg/httpx/common/stringz"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func xegexpjs(reg string, resp string) (reslut1 [][]string) {
	reg1 := regexp.MustCompile(reg)
	if reg1 == nil {
		log.Println("regexp err")
		return nil
	}
	result1 := reg1.FindAllStringSubmatch(resp, -1)
	return result1
}

func getfavicon(httpbody string, turl string) (hash string, md5 string) {
	faviconpaths := xegexpjs(`href="(.*?favicon....)"`, httpbody)
	var faviconpath string
	u, err := url.Parse(strings.TrimSpace(turl))
	if err != nil {
		panic(err)
	}
	turl = u.Scheme + "://" + u.Host
	if len(faviconpaths) > 0 {
		fav := faviconpaths[0][1]
		if fav[:2] == "//" {
			faviconpath = "http:" + fav
		} else {
			if fav[:4] == "http" {
				faviconpath = fav
			} else {
				faviconpath = turl + "/" + fav
			}

		}
	} else {
		faviconpath = turl + "/favicon.ico"
	}
	return favicohash(faviconpath)
}

// 计算hash，md5
func GetHahsMd5(body []byte) (hash string, md5R string) {
	faviconMMH3 := fmt.Sprintf("%d", stringz.FaviconHash(body))
	srcCode := md5.Sum(body)
	faviconmd5 := strings.ToLower(fmt.Sprintf("%x", srcCode))
	return faviconMMH3, faviconmd5
}

// 求url host hash和md5
//
//	key: cache key
func Favicohash4key(host, key string) (hash string, md5R string) {
	k1 := host + key
	body, err := util.Cache1.Get(k1)
	if nil != err && 0 == len(body) {
		timeout := time.Duration(8 * time.Second)
		var tr *http.Transport
		if util.HttpProxy != "" {
			uri, _ := url.Parse(strings.TrimSpace(util.HttpProxy))
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
		client := http.Client{
			Timeout:   timeout,
			Transport: tr,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse /* 不进入重定向 */
			},
		}
		resp, err := client.Get(host)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				body, err = ioutil.ReadAll(resp.Body)
				util.Cache1.Put(k1, body)
				if err != nil {
					//log.Println("favicon file read error: ", err)
					return "0", ""
				}
			}
		}
	}
	if 0 == len(body) {
		return "0", ""
	}
	return GetHahsMd5(body)
}

// 基于缓存，提高效率
func favicohash(host string) (hash string, md5R string) {
	return Favicohash4key(host, "favicohash")
}
