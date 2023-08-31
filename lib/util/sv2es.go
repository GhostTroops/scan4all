package util

import (
	"bytes"
	"fmt"
	Const "github.com/hktalent/go-utils"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

var n1 int
var nThreads chan struct{}
var EsUrl string
var EnableEsSv bool

func initEs() {
	EnableEsSv = GetValAsBool("EnableEsSv")
	EsUrl = GetValByDefault("EsUrl", "https://127.0.0.1:8081/%s_index/_doc/%s")
	if EnableEsSv {
		n1 = GetValAsInt("esthread", 4)
		log.Printf("es 初始化线程数 = %d, EsUrl = %s", n1, EsUrl)
		nThreads = make(chan struct{}, n1)
	}
}

func init() {
	RegInitFunc(func() {
		// 保存数据也采用统一的线程池
		if nil != EngineFuncFactory {
			EngineFuncFactory(Const.ScanType_SaveEs, func(evt *Const.EventData, args ...interface{}) {
				SendReq(args[0].(interface{}), args[1].(string), args[2].(string))
			})
		}
	})
}

func Log(v ...any) {
	log.Println(v...)
}

// 简单结果
type SimpleVulResult struct {
	Url      string        `json:"url"`
	VulKind  string        `json:"vulKind"`   // 结果分类
	VulType  string        `json:"vulType"`   // 漏洞类型
	Payload  string        `json:"payload"`   // 攻击、检测一类的结果时，当前的payload
	Msg      string        `json:"msg"`       // 其他消息
	ScanType uint64        `json:"scan_type"` // 扫描类型
	ScanData []interface{} `json:"scan_data"` // 扫描结果，例如 masscan端口扫描、nmap
}

// 一定得有全局得线程等待
func SendAnyData(data interface{}, szType string) {
	if EnableEsSv {
		data1, _ := json.Marshal(data)
		if 0 < len(data1) {
			k := GetSha1(data)
			SendEvent(&Const.EventData{EventType: Const.ScanType_SaveEs, EventData: []interface{}{data, k, szType}}, Const.ScanType_SaveEs)
		}
	}
}

// k is id
func SendAData[T any](k string, data []T, szType string) {
	if 0 < len(data) && EnableEsSv {
		m2 := make(map[string]interface{})
		m2[k] = data
		SendEvent(&Const.EventData{EventType: Const.ScanType_SaveEs, EventData: []interface{}{m2, k, szType}}, Const.ScanType_SaveEs)
		//SendReq(m2, k, szType)
		//log.Printf("%+v\n", data)
	}
}

// es 需要基于buffer，避免太频繁
// 发送数据到ES
//
//	data1数据
//	id 数据计算出来的id
//	szType 类型，决定 es不通的索引分类
func SendReq(data1 interface{}, id string, szType string) {
	if !EnableEsSv {
		return
	}
	//log.Println("EnableEsSv = ", EnableEsSv, " id= ", id, " type = ", szType)
	nThreads <- struct{}{}
	defer func() {
		<-nThreads
	}()
	szUrl := fmt.Sprintf(EsUrl, szType, url.QueryEscape(id))
	//log.Println("logs EsUrl = ", EsUrl)
	m1 := map[string]string{
		"User-Agent":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15",
		"Content-Type": "application/json;charset=UTF-8",
	}
	c1 := GetClient(szUrl, map[string]interface{}{"UseHttp2": true})
	c1.ErrLimit = 10000
	c1.ErrCount = 0
	data, _ := json.Marshal(data1)
	c1.UseHttp2 = true
	c1.DoGetWithClient4SetHd(c1.GetClient4Http2(), szUrl, "POST", bytes.NewReader(data), func(resp *http.Response, err error, szU string) {
		if nil != err {
			log.Println("pphLog.DoGetWithClient4SetHd ", err)
		} else {
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if nil == err && 0 < len(body) {
				Log("Es save result ", resp.StatusCode, string(body))
			} else if nil != err {
				Log(err)
			}
		}
	}, func() map[string]string {
		return m1
	}, true)
}
