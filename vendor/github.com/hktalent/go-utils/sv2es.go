package go_utils

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

var n1 int
var nThreads chan struct{}
var EsUrl string
var enableEsSv bool

type ESaveType string

const (
	Naabu     ESaveType = "naabu"
	Httpx     ESaveType = "httpx"
	Hydra     ESaveType = "hydra"
	Nmap      ESaveType = "nmap"
	Scan4all  ESaveType = "scan4all"
	Subfinder ESaveType = "subfinder"
)

func init() {
	RegInitFunc(func() {
		enableEsSv = GetValAsBool("enableEsSv")
		EsUrl = GetValByDefault("EsUrl", "http://127.0.0.1:9200/%s_index/_doc/%s")
		if enableEsSv {
			n1 = GetValAsInt("esthread", 4)
			log.Printf("es Initialize the number of threads = %d, EsUrl = %s", n1, EsUrl)
			nThreads = make(chan struct{}, n1)
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
	ScanType int           `json:"scan_type"` // 扫描类型
	ScanData []interface{} `json:"scan_data"` // 扫描结果，例如 masscan端口扫描、nmap
}

// 一定得有全局得线程等待
func SendAnyData(data interface{}, szType ESaveType) {
	DoSyncFunc(func() {
		data1, _ := Json.Marshal(data)
		if 0 < len(data1) && enableEsSv {
			hasher := sha1.New()
			hasher.Write(data1)
			k := hex.EncodeToString(hasher.Sum(nil))
			SendReq(data, k, szType)
		}
	})
}

// k is id
func SendAData[T any](k string, data []T, szType ESaveType) {
	if 0 < len(data) && enableEsSv {
		m2 := make(map[string]interface{})
		m2[k] = data
		SendReq(m2, k, szType)
		log.Printf("%+v\n", data)
	}
}

// 发送数据到ES
func SendReq(data1 interface{}, id string, szType ESaveType) {
	DoSyncFunc(func() {
		if !enableEsSv {
			return
		}
		//log.Println("enableEsSv = ", enableEsSv, " id= ", id, " type = ", szType)
		data, _ := Json.Marshal(data1)
		nThreads <- struct{}{}
		defer func() {
			<-nThreads
		}()
		//log.Println("EsUrl = ", EsUrl)
		url1 := fmt.Sprintf(EsUrl, szType, url.QueryEscape(id))
		//log.Println("url = ", url)
		req, err := http.NewRequest("POST", url1, bytes.NewReader(data))
		if err != nil {
			Log(fmt.Sprintf("%s error %v", id, err))
			return
		}
		// 取消全局复用连接
		// tr := http.Transport{DisableKeepAlives: true}
		// client := http.Client{Transport: &tr}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15")
		req.Header.Add("Content-Type", "application/json;charset=UTF-8")
		// keep-alive
		req.Header.Add("Connection", "close")
		req.Close = true

		resp, err := http.DefaultClient.Do(req)
		//log.Println("url = ", url)
		if resp != nil {
			defer func() {
				err := resp.Body.Close() // resp 可能为 nil，不能读取 Body
				if nil != err {
					Log(fmt.Sprintf("%s error %v", id, err))
				}
			}()
		}
		if err != nil {
			Log(fmt.Sprintf("%s error %v", id, err))
			return
		}

		body, err := ioutil.ReadAll(resp.Body)
		if nil == err && 0 < len(body) {
			//Log("Es save result ", string(body))
		} else {
			Log(err)
		}
		//_, err = io.Copy(ioutil.Discard, resp.Body) // 手动丢弃读取完毕的数据
		// json.NewDecoder(resp.Body).Decode(&data)
		// req.Body.Close()
		// go http.Post(resUrl, "application/json",, post_body)
	})
}
