package util

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/codegangsta/inject"
	"github.com/corpix/uarand"
	"github.com/hbakhtiyor/strsim"
	"github.com/karlseguin/ccache"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
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
	rsps, _, _, err := GetResponse(username, password, urlstring, method, postdata, isredirect, headers)
	return rsps, err
}

// client缓存
var clientHttpCc *ccache.Cache

func InitCHcc() {
	if nil == clientHttpCc {
		configure := ccache.Configure()
		configure = configure.MaxSize(10000)
		clientHttpCc = ccache.New(configure)
	}
}

func init() {
	RegInitFunc(func() {
		InitCHcc()
	})
}

var mUrls = make(map[string]string)

func GetClient4Cc(szUrl string) *http.Client {
	InitCHcc()
	oU, err := url.Parse(szUrl)
	if nil == err {
		if o := clientHttpCc.Get(oU.Host); nil != o {
			if v, ok := o.Value().(*http.Client); ok {
				return v
			}
		}
	} else {
		log.Println("GetClient4Cc url.Parse is err ", err, szUrl)
	}
	return nil
}
func GetClient(szUrl string) *http.Client {
	oU, err := url.Parse(szUrl)
	if nil != err {
		log.Printf("GetClient url:%s url.Parse err:%v\n", szUrl, err)
		return nil
	}
	client := GetClient4Cc(szUrl)
	if nil != client {
		return client
	}
	var tr *http.Transport
	tr = &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:           100,
		MaxIdleConnsPerHost:    1024,
		TLSHandshakeTimeout:    0 * time.Second,
		IdleConnTimeout:        90 * time.Second,
		ExpectContinueTimeout:  1 * time.Second,
		MaxResponseHeaderBytes: 4096, // net/http default is 10Mb
		TLSClientConfig: &tls.Config{
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: false,
	}
	if HttpProxy != "" {
		uri, _ := url.Parse(strings.TrimSpace(HttpProxy))
		tr.Proxy = http.ProxyURL(uri)
	}

	client = &http.Client{
		Timeout:   time.Duration(20) * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	mUrls[oU.Host] = ""
	clientHttpCc.Set(oU.Host, client, defaultInteractionDuration)
	return client
}

func CloseHttpClient(szUrl string) {
	oU, _ := url.Parse(szUrl)
	client := GetClient4Cc(szUrl)
	if nil != client {
		client.CloseIdleConnections()
	}
	clientHttpCc.Delete(oU.Host)
}
func CloseAllHttpClient() {
	for k, _ := range mUrls {
		CloseHttpClient("http://" + k)
	}
}

// 数组去重
func SliceRemoveDuplicates(slice []string) []string {
	if nil == slice || 0 == len(slice) {
		return slice
	}
	sort.Strings(slice)
	i := 0
	var j int
	for {
		if i >= len(slice)-1 {
			break
		}
		for j = i + 1; j < len(slice) && slice[i] == slice[j]; j++ {
		}
		slice = append(slice[:i+1], slice[j:]...)
		i++
	}
	return slice
}

// 若干参数依赖注入到对象 obj中
//  util.MergeParms2Obj(&ms, args...)
func MergeParms2Obj(obj interface{}, args ...interface{}) interface{} {
	if nil != args && 0 < len(args) {
		in := inject.New()
		for _, i := range args {
			in.Map(i)
		}
		in.Apply(obj)
	}
	return obj
}

func GetResponse(username string, password string, urlstring string, method string, postdata string, isredirect bool, headers map[string]string) (resp1 *Response, reqbody, location string, err error) {
	client := GetClient(urlstring)
	if nil == client {
		return nil, "", "", errors.New(urlstring + " client is nil")
	}
	if isredirect {
		jar, _ := cookiejar.New(nil)
		client.Jar = jar
	} else {
		client.Jar = nil
	}
	req, err := http.NewRequest(strings.ToUpper(method), urlstring, strings.NewReader(postdata))
	if err != nil {
		return nil, "", "", err
	}
	if "" != username && "" != password {
		req.SetBasicAuth(username, password)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Add("User-Agent", uarand.GetRandom())
	//req.Header.Add("Connection", "keep-alive")// http1.1 默认 开启
	SetHeader(&req.Header)
	for k, v := range headers {
		req.Header.Add(k, v)
	}

	var resp *http.Response
	// resp, err = tr.RoundTrip(req)
	resp, err = client.Do(req)
	defer func() {
		req.Body.Close()
		if nil != resp {
			//io.Copy(ioutil.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	if err != nil {
		if nil != resp {
			io.Copy(ioutil.Discard, resp.Body)
		}
		//防止空指针
		return &Response{"999", 999, "", nil, 0, "", ""}, "", "", err
	}

	if body, err := ioutil.ReadAll(resp.Body); err == nil {
		reqbody = string(body)
	}
	if resplocation, err := resp.Location(); err == nil {
		location = resplocation.String()
	}
	return &Response{resp.Status, resp.StatusCode, reqbody, &resp.Header, len(reqbody), resp.Request.URL.String(), location}, reqbody, location, nil
}

// 需要考虑缓存
//  1、缓解网络不好的情况
//  2、缓存有效期为当天
//  3、缓存命中需和请求的数据完全匹配
func HttpRequset(urlstring string, method string, postdata string, isredirect bool, headers map[string]string) (*Response, error) {
	rsps, _, _, err := GetResponse("", "", urlstring, method, postdata, isredirect, headers)
	return rsps, err
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
