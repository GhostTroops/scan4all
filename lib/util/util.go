package util

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/goSqlite_gorm/pkg/models"
	"github.com/codegangsta/inject"
	"github.com/corpix/uarand"
	"github.com/hbakhtiyor/strsim"
	"github.com/hktalent/PipelineHttp"
	"github.com/karlseguin/ccache"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	HttpProxy   string // 代理
	CeyeApi     string // Ceye api
	CeyeDomain  string // Ceye domain
	Fuzzthreads = 32   // 2,4,8,16,32,采用2的N次方的数字
)

const (
	// Distributed API Server，服务器
	G_Server = "https://das.51pwn.com"
)

// http密码爆破
func HttpRequsetBasic(username string, password string, urlstring string, method string, postdata string, isredirect bool, headers map[string]string) (*Response, error) {
	rsps, _, _, err := GetResponse(username, password, urlstring, method, postdata, isredirect, headers)
	return rsps, err
}

// client缓存
var clientHttpCc *ccache.Cache

// 获取一个内存对象
//
//	如果c不是nil，就不再创建新的
func GetMemoryCache(nMaxSize int64, c *ccache.Cache) *ccache.Cache {
	if nil == c {
		configure := ccache.Configure()
		configure = configure.MaxSize(nMaxSize)
		c = ccache.New(configure)
	}
	return c
}

// 初始化client cache
func InitCHcc() {
	clientHttpCc = GetMemoryCache(10000, clientHttpCc)
}

func init() {
	RegInitFunc(func() {
		InitCHcc()
	})
}

var mUrls sync.Map

func GetClient4Cc(szUrl string) *PipelineHttp.PipelineHttp {
	InitCHcc()
	oU, err := url.Parse(szUrl)
	if nil == err {
		if o := clientHttpCc.Get(oU.Host); nil != o {
			//if o := clientHttpCc.Get("_ccClient"); nil != o && oU.Hostname() != "" {
			if v, ok := o.Value().(*PipelineHttp.PipelineHttp); ok {
				return v
			}
		}
	} else {
		log.Println("GetClient4Cc url.Parse is err ", err, szUrl)
	}
	return nil
}
func PutClientCc(szUrl string, c *PipelineHttp.PipelineHttp) {
	CloseHttpClient(szUrl)
	oU, _ := url.Parse(szUrl)
	clientHttpCc.Delete(oU.Scheme + oU.Host)
	clientHttpCc.Set(oU.Scheme+oU.Host, c, defaultInteractionDuration)
}

//var G_hc *http.Client

func GetClient(szUrl string, pms ...map[string]interface{}) *PipelineHttp.PipelineHttp {
	oU, err := url.Parse(szUrl)
	if nil != err {
		log.Printf("GetClient url:%s url.Parse err:%v\n", szUrl, err)
		return nil
	}
	client := GetClient4Cc(szUrl)
	if nil != client {
		return client
	}
	if 0 == len(pms) {
		pms = []map[string]interface{}{
			map[string]interface{}{
				"max_idle_conns_per_host": 50,
				"max_conns_per_host":      50,
				"max_idle_conns":          50,
				"err_limit":               90000,
			},
		}
	}
	client = PipelineHttp.NewPipelineHttp(pms...)
	//if nil == G_hc {
	//	G_hc = client.GetClient(nil)
	//}
	//client.Client = G_hc
	mUrls.Store(oU.Host, "")
	clientHttpCc.Delete(oU.Scheme + oU.Host)
	clientHttpCc.Set(oU.Host, client, defaultInteractionDuration)
	//clientHttpCc.Set("_ccClient", client, defaultInteractionDuration)

	return client
}

func CloseHttpClient(szUrl string) {
	oU, _ := url.Parse(szUrl)
	client := GetClient4Cc(szUrl)
	if nil != client {
		client.Close()
	}
	clientHttpCc.Delete(oU.Scheme + oU.Host)
}

func CloseAllHttpClient() {
	mUrls.Range(func(k, value any) bool {
		if s, ok := k.(string); ok {
			CloseHttpClient("http://" + s)
			CloseHttpClient("https://" + s)
		}
		return true
	})
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
//
//	util.MergeParms2Obj(&ms, args...)
//	使用 inject 注入 struct 需要注意的时，每个inject的类型不一样，如果一样的，必须使用类型别名，否则盲注会出问题
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

// 返回限流的reader
func GetLimitReader(i *http.Response) io.ReadCloser {
	CheckResp(i.Request.URL.String(), i)
	return io.NopCloser(&io.LimitedReader{R: i.Body, N: int64(GetValAsInt("LimitReader", 819200))})
}

func GetResponse(username string, password string, urlstring string, method string, postdata string, isredirect bool, headers map[string]string) (resp1 *Response, reqbody, location string, err error) {
	client := GetClient(urlstring)
	if nil == client {
		return nil, "", "", errors.New(urlstring + " client is nil")
	}
	//client.SetCtx(Ctx_global)
	if !isredirect && nil != client.Client {
		client.Client.CheckRedirect = nil
	}
	client.DoGetWithClient4SetHd(client.Client, urlstring, strings.ToUpper(method), strings.NewReader(postdata), func(resp *http.Response, err1 error, szU string) {
		if err1 != nil {
			if nil != resp {
				defer resp.Body.Close()
				//io.Copy(ioutil.Discard, resp.Body)
			}
			//log.Printf("%s %v", urlstring, err1)
			resp1, reqbody, location, err = &Response{"999", 999, "", nil, 0, "", "", ""}, "", "", err1
		} else {
			if body, err1 := ioutil.ReadAll(GetLimitReader(resp)); err1 == nil {
				reqbody = string(body)
			}
			if relocation, err1 := resp.Location(); err1 == nil {
				location = relocation.String()
			}
			resp1, reqbody, location, err = &Response{resp.Status, resp.StatusCode, reqbody, &resp.Header, len(reqbody), resp.Request.URL.String(), location, resp.Proto}, reqbody, location, nil
		}
	}, func() map[string]string {
		hd001 := map[string]string{}
		if "" != username && "" != password {
			hd001["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
		}
		hd001["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
		hd001["User-Agent"] = uarand.GetRandom()
		SetHeader4Map(&hd001)
		for k, v := range headers {
			hd001[k] = v
		}
		return hd001
	}, true)
	return resp1, reqbody, location, err
}

// 需要考虑缓存
//
//	1、缓解网络不好的情况
//	2、缓存有效期为当天
//	3、缓存命中需和请求的数据完全匹配
func HttpRequset(urlstring string, method string, postdata string, isredirect bool, headers map[string]string) (*Response, error) {
	rsps, _, _, err := GetResponse("", "", urlstring, method, postdata, isredirect, headers)
	if nil == err && nil == rsps {
		err = errors.New("unknown err HttpRequset -> GetResponse " + urlstring)
	}
	return rsps, err
}

func TestIsWeb(a *[]string) (a1 *[]string, b *[]string) {
	var aHttp, noHttp []string
	for _, k := range *a {
		if _, _, ok := TestIsWeb01(k); ok {
			aHttp = append(aHttp, k)
		} else {
			noHttp = append(noHttp, k)
		}
	}
	return &aHttp, &noHttp
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

func RetrieveCallInfo() *map[string]interface{} {
	pc, file, line, _ := runtime.Caller(2)
	_, fileName := path.Split(file)
	parts := strings.Split(runtime.FuncForPC(pc).Name(), ".")
	pl := len(parts)
	packageName := ""
	funcName := parts[pl-1]

	if parts[pl-2][0] == '(' {
		funcName = parts[pl-2] + "." + funcName
		packageName = strings.Join(parts[0:pl-2], ".")
	} else {
		packageName = strings.Join(parts[0:pl-1], ".")
	}

	return &map[string]interface{}{
		"packageName": packageName,
		"fileName":    fileName,
		"funcName":    funcName,
		"line":        line,
	}
}

// convert  bufio.Scanner to io.Reader
func ScannerToReader(scanner *bufio.Scanner) io.Reader {
	reader, writer := io.Pipe()
	go func() {
		defer writer.Close()
		for scanner.Scan() {
			writer.Write(scanner.Bytes())
		}
	}()

	return reader
}

// 纯粹发送数据到目标机器
func SendData2Url(szUrl string, data1 interface{}, m1 *map[string]string, fnCbk func(resp *http.Response, err error, szU string)) {
	data, _ := json.Marshal(data1)
	c1 := GetClient(szUrl)
	c1.DoGetWithClient4SetHd(c1.Client, szUrl, "POST", bytes.NewReader(data), func(resp1 *http.Response, err error, szU string) {
		if nil != resp1 {
			resp1.Body = GetLimitReader(resp1)
		}
		fnCbk(resp1, err, szU)
	}, func() map[string]string {
		return *m1
	}, true)
}

func DeepCopy(src, dist interface{}) (err error) {
	buf := bytes.Buffer{}
	if err = gob.NewEncoder(&buf).Encode(src); err != nil {
		return
	}
	return gob.NewDecoder(&buf).Decode(dist)
}

type EngineFuncType func(evt *models.EventData, args ...interface{})

// 工厂方法
//
//	便于同一、规范引擎调用的方法、参数约束
var EngineFuncFactory func(nT int64, fnCbk interface{})

// 全局引擎
var G_Engine interface{}
var SendEvent func(evt *models.EventData, argsTypes ...int64)

// 反射调用
func Invoke(iFunc interface{}, args ...interface{}) {
	if nil != args && 0 < len(args) {
		in := inject.New()
		for _, i := range args {
			in.Map(i)
		}
		in.Invoke(iFunc)
	}
}

func DoGet(szUrl string, hd map[string]string) (resp *http.Response, err error) {
	if c1 := GetClient(szUrl); nil != c1 {
		c1.DoGetWithClient4SetHd(nil, szUrl, "GET", nil, func(resp1 *http.Response, err1 error, szU string) {
			if nil != resp1 {
				resp1.Body = GetLimitReader(resp1)
			}
			resp = resp1
			err = err1
		}, func() map[string]string {
			return hd
		}, false)
	}
	return resp, err
}

func DoPost(szUrl string, hd map[string]string, data io.Reader) (resp *http.Response, err error) {
	if c1 := GetClient(szUrl); nil != c1 {
		c1.DoGetWithClient4SetHd(nil, szUrl, "POST", data, func(resp1 *http.Response, err1 error, szU string) {
			if nil != resp1 {
				resp1.Body = GetLimitReader(resp1)
			}
			resp = resp1
			err = err1
		}, func() map[string]string {
			return hd
		}, false)
	}
	return resp, err
}
