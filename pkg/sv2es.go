package pkg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
)

var n1 int
var nThreads chan struct{}
var esUrl string
var enableEsSv string

func init() {
	enableEsSv = GetVal("enableEsSv")
	if "true" == enableEsSv {
		esUrl = GetVal("esUrl")
		n1, _ = strconv.Atoi(GetValByDefault("esthread", "4"))
		//log.Println("es 初始化线程数 = ", n1)
		nThreads = make(chan struct{}, n1)
	} else {
		Log(mData)
	}
}

func Log(v ...any) {
	log.Println(v...)
}

func SendAData[T any](k string, data []T, szType string) {
	if 0 < len(data) && "true" == GetVal("enableEsSv") {
		m2 := make(map[string]interface{})
		m2[k] = data
		go SendReq(m2, k, szType)
	}
}

func SendReq(data1 interface{}, id, szType string) {
	if "true" != enableEsSv {
		return
	}
	//log.Println("enableEsSv = ", enableEsSv, " id= ", id, " type = ", szType)
	data, _ := json.Marshal(data1)
	nThreads <- struct{}{}
	defer func() {
		<-nThreads
	}()
	url := esUrl + szType + "_index/_doc/" + url.QueryEscape(id)
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
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
	if nil == err {
		Log(body)
	} else {
		Log(err)
	}
	//_, err = io.Copy(ioutil.Discard, resp.Body) // 手动丢弃读取完毕的数据
	// json.NewDecoder(resp.Body).Decode(&data)
	// req.Body.Close()
	// go http.Post(resUrl, "application/json",, post_body)
}
