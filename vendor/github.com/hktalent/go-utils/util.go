package go_utils

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/codegangsta/inject"
	"github.com/corpix/uarand"
	"github.com/hbakhtiyor/strsim"
	"github.com/hktalent/PipelineHttp"
	jsoniter "github.com/json-iterator/go"
	"github.com/karlseguin/ccache"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
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
	Json        = jsoniter.ConfigCompatibleWithStandardLibrary
)

const (
	// Distributed API Server，服务器
	G_Server = "https://DAS.51pwn.com"
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

var mUrls = make(map[string]string)

func GetClient4Cc(szUrl string) *PipelineHttp.PipelineHttp {
	InitCHcc()
	oU, err := url.Parse(szUrl)
	if nil == err {
		if o := clientHttpCc.Get(oU.Host); nil != o {
			if v, ok := o.Value().(*PipelineHttp.PipelineHttp); ok {
				return v
			}
		}
	} else {
		log.Println("GetClient4Cc url.Parse is err ", err, szUrl)
	}
	return nil
}
func GetClient(szUrl string) *PipelineHttp.PipelineHttp {
	oU, err := url.Parse(szUrl)
	if nil != err {
		log.Printf("GetClient url:%s url.Parse err:%v\n", szUrl, err)
		return nil
	}
	client := GetClient4Cc(szUrl)
	if nil != client {
		return client
	}

	client = PipelineHttp.NewPipelineHttp()
	mUrls[oU.Host] = ""
	clientHttpCc.Set(oU.Host, client, defaultInteractionDuration)
	return client
}

func CloseHttpClient(szUrl string) {
	oU, _ := url.Parse(szUrl)
	client := GetClient4Cc(szUrl)
	if nil != client {
		client.Close()
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

func GetResponse(username string, password string, urlstring string, method string, postdata string, isredirect bool, headers map[string]string) (resp1 *Response, reqbody, location string, err error) {
	client := GetClient(urlstring)
	if nil == client {
		return nil, "", "", errors.New(urlstring + " client is nil")
	}
	client.SetCtx(Ctx_global)
	if !isredirect {
		client.Client.CheckRedirect = nil
	}
	client.DoGetWithClient4SetHd(client.Client, urlstring, strings.ToUpper(method), strings.NewReader(postdata), func(resp *http.Response, err1 error, szU string) {
		if err1 != nil {
			if nil != resp {
				io.Copy(ioutil.Discard, resp.Body)
			}
			log.Printf("%s %v", urlstring, err1)
			resp1, reqbody, location, err = &Response{"999", 999, "", nil, 0, "", ""}, "", "", err1
		} else {
			if body, err1 := ioutil.ReadAll(resp.Body); err1 == nil {
				reqbody = string(body)
			}
			if relocation, err1 := resp.Location(); err1 == nil {
				location = relocation.String()
			}
			resp1, err = &Response{resp.Status, resp.StatusCode, reqbody, &resp.Header, len(reqbody), resp.Request.URL.String(), location}, nil
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
	return rsps, err
}

func TestIsWeb(a *[]string) (a1 *[]string, b *[]string) {
	var aHttp, noHttp []string
	for _, k := range *a {
		if _, _, ok := TestIs404(k); ok {
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

var CloseCbk []func()

func RegCloseCbk(f func()) {
	CloseCbk = append(CloseCbk, f)
}

// 关闭所有资源
func CloseAll() {
	StopAll()
	for _, ckb := range CloseCbk {
		ckb()
	}
	ReleaseFunc.DoFunc()
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

const (
	MacLineSize = 10 * 1024 * 1024 // 10M
)

// 读取命令行管道输入
func ReadStdIn(out chan *string) {
	if nil != os.Stdin {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, MacLineSize), MacLineSize)
		for scanner.Scan() {
			value := strings.TrimSpace(scanner.Text())
			out <- &value
		}
		close(out)
	}
}
