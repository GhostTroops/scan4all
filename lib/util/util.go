package util

import (
	"crypto/tls"
	"fmt"
	"github.com/corpix/uarand"
	"github.com/hbakhtiyor/strsim"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"
)

var (
	HttpProxy   string // 代理
	CeyeApi     string // Ceye api
	CeyeDomain  string // Ceye domain
	Fuzzthreads = 32   // 2,4,8,16,32,采用2的N次方的数字
)

// http密码爆破
func HttpRequsetBasic(username string, password string, urlstring string, method string, postdata string, isredirect bool, headers map[string]string) (*Response, error) {
	var tr *http.Transport
	var err error
	if HttpProxy != "" {
		uri, _ := url.Parse(strings.TrimSpace(HttpProxy))
		tr = &http.Transport{
			MaxIdleConnsPerHost: -1,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:   true,
			Proxy:               http.ProxyURL(uri),
			IdleConnTimeout:     15 * time.Second,
		}
	} else {
		tr = &http.Transport{
			MaxIdleConnsPerHost: -1,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:   true,
			IdleConnTimeout:     15 * time.Second,
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
	req, err := http.NewRequest(strings.ToUpper(method), urlstring, strings.NewReader(postdata))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("User-Agent", uarand.GetRandom())
	SetHeader(&req.Header)
	for v, k := range headers {
		req.Header[v] = []string{k}
	}
	var resp *http.Response

	// resp, err = tr.RoundTrip(req)
	resp, err = client.Do(req)
	if err != nil {
		//防止空指针
		return &Response{"999", 999, "", nil, 0, "", ""}, err
	}
	var location string
	var reqbody string
	defer resp.Body.Close()
	if body, err := ioutil.ReadAll(resp.Body); err == nil {
		reqbody = string(body)
	}
	if resplocation, err := resp.Location(); err == nil {
		location = resplocation.String()
	}
	return &Response{resp.Status, resp.StatusCode, reqbody, &resp.Header, len(reqbody), resp.Request.URL.String(), location}, nil
}

// 需要考虑缓存
//  1、缓解网络不好的情况
//  2、缓存有效期为当天
//  3、缓存命中需和请求的数据完全匹配
func HttpRequset(urlstring string, method string, postdata string, isredirect bool, headers map[string]string) (*Response, error) {
	var tr *http.Transport
	if HttpProxy != "" {
		uri, _ := url.Parse(strings.TrimSpace(HttpProxy))
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
	req, err := http.NewRequest(strings.ToUpper(method), urlstring, strings.NewReader(postdata))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("User-Agent", uarand.GetRandom())
	// 设置全局自定义头、cookie信息
	SetHeader(&req.Header)
	for v, k := range headers {
		req.Header[v] = []string{k}
	}
	resp, err := client.Do(req)
	if err != nil {
		//防止空指针
		return &Response{"999", 999, "", nil, 0, "", ""}, err
	}
	var location string
	var reqbody string
	defer resp.Body.Close()
	if body, err := ioutil.ReadAll(resp.Body); err == nil {
		reqbody = string(body)
	}
	if resplocation, err := resp.Location(); err == nil {
		location = resplocation.String()
	}
	return &Response{resp.Status, resp.StatusCode, reqbody, &resp.Header, len(reqbody), resp.Request.URL.String(), location}, nil
}

func Dnslogchek(randomstr string) bool {
	urlStr := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=dns&filter=%s", CeyeApi, randomstr)
	if resp, err := HttpRequset(urlStr, "GET", "", false, nil); err == nil {
		if !StrContains(resp.Body, `"data": []`) && strings.Contains(resp.Body, `{"code": 200, "message": "OK"}`) { // api返回结果不为空
			return true
		}
	}
	return false
}

func RandomStr() string {
	lowercase := "1234567890abcdefghijklmnopqrstuvwxyz"
	randSource := rand.New(rand.NewSource(time.Now().Unix()))
	var (
		letterIdxBits = 6                    // 6 bits to represent a letter index
		letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
		letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
	)
	randBytes := make([]byte, 8)
	for i, cache, remain := 8-1, randSource.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = randSource.Int63(), letterIdxMax
		}
		if idx := int(cache) & int(letterIdxMask); idx < len(lowercase) {
			randBytes[i] = lowercase[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return string(randBytes)
}

// 判断 i 是否存在slice中
func SliceInAny[T any](i T, slice []T) bool {
	for _, j := range slice {
		if reflect.DeepEqual(i, j) {
			return true
		}
	}
	return false
}

// 判断 i 是否存在slice中
func IntInSlice(i int, slice []int) bool {
	if slice == nil {
		return false
	}
	sort.Ints(slice)
	index := sort.SearchInts(slice, i)
	if index < len(slice) && slice[index] == i {
		return true
	}
	return false
}

// 判断 str 是否存在slice中
func StringInSlice(str string, slice []string) bool {
	if slice == nil {
		return false
	}
	sort.Strings(slice)
	index := sort.SearchStrings(slice, str)
	if index < len(slice) && slice[index] == str {
		return true
	}
	return false
}

func SliceInString(str string, slice []string) bool {
	if slice == nil {
		return false
	}
	for _, v := range slice {
		// 基于相似度计算
		if 0.9 < strsim.Compare(str, v) {
			return true
		}
	}
	return false
}

var a1 = strings.Split("app,net,org,vip,cc,cn,co,io,com,gov.edu", ",")

// 兼容hacker one 域名表示方式,以下格式支持
// *.xxx.com
// *.xxx.xx1.*
func Convert2Domains(x string) []string {
	aRst := []string{}
	x = strings.TrimSpace(x)
	if "*.*" == x || -1 < strings.Index(x, ".*.") {
		return aRst
	}
	if -1 < strings.Index(x, "(*).") {
		x = x[4:]
	}
	if -1 < strings.Index(x, "*.") {
		x = x[2:]
	}
	if 2 > strings.Index(x, "*") {
		x = x[1:]
	}
	if -1 < strings.Index(x, ".*") {
		x = x[0 : len(x)-2]
		for _, j := range a1 {
			aRst = append(aRst, x+"."+j)
		}
	} else {
		aRst = append(aRst, x)
	}
	return aRst
}

// 关闭所有资源
func CloseAll() {
	StopAll()
	// clear
	// 程序都结束了，没有必要清理内存了
	// fingerprint.ClearData()
	log4jsv.Range(func(key, value any) bool {
		log4jsv.Store(key, nil)
		log4jsv.Delete(key)
		return true
	})
	if nil != Cache1 {
		Cache1.Close()
		Cache1 = nil
	}
	Close()
	CloseCache()
	if runtime.GOOS == "windows" || GetValAsBool("autoRmCache") {
		os.RemoveAll(GetVal(CacheName))
	}
}
