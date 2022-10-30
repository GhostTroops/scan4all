package util

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"github.com/hktalent/51pwnPlatform/pkg/models"
	"log"
	"os"
	"runtime"
	"strings"
)

// out filename
var Output = ""

//// 调用方法名作为插件名
func GetPluginName(defaultVal string) string {
	pc, _, _, ok := runtime.Caller(1)
	details := runtime.FuncForPC(pc)
	if ok && details != nil {
		return details.Name()
	}
	return defaultVal
}

// 1、优化代码，统一结果输出，便于维护
func SendLog(szUrl, szVulType, Msg, Payload string) {
	v := &SimpleVulResult{
		Url:     szUrl,
		VulKind: string(Scan4all),
		VulType: szVulType,
		Payload: Payload,
		Msg:     strings.TrimSpace(Msg) + " " + szVulType,
	}
	SendAnyData(v, Scan4all)
	writeoutput(v)
}

// 专门发送改造后的引擎函数执行结果
func SendEngineLog(evt *models.EventData, nCurType int64, data ...interface{}) {
	if nil != data && 0 < len(data) {
		v := &SimpleVulResult{
			Url:      evt.Task.ScanWeb,
			VulKind:  string(Scan4all),
			ScanType: nCurType,
			ScanData: data,
		}
		s := GetEsType(nCurType)
		if "" != s {
			SendAnyData(v, s)
			writeoutput(v)
		} else {
			log.Printf("SendEngineLog can not find type %d\n", nCurType)
		}
	}
}

// 专门发送改造后的引擎函数执行结果
func SendEngineLog4Url(Url string, nCurType int64, data ...interface{}) {
	if nil != data && 0 < len(data) {
		v := &SimpleVulResult{
			Url:      Url,
			VulKind:  string(Scan4all),
			ScanType: nCurType,
			ScanData: data,
		}
		SendAnyData(v, Scan4all)
		writeoutput(v)
	}
}

// 避免并发写磁盘导致堵塞
var OutLogV chan interface{}

// 基于缓存写日志
func WriteLog2File(v1 interface{}) {
	if 1 > len(Output) {
		return
	}
	f, err := os.OpenFile(Output, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Could not create output fiale '%s': %s\n", Output, err)
		return
	}
	defer f.Close()
	var buf *bufio.Writer
	var buf1 *csv.Writer

	if strings.HasSuffix(Output, ".csv") {
		buf1 = csv.NewWriter(f)
	} else {
		buf = bufio.NewWriter(f)
	}
	var fnWt = func(v interface{}) {

		if nil != buf1 {
			var a []string
			buf1.Write(a)
			buf1.Flush()
		} else if nil != buf {
			var szLog string
			szLog = fmt.Sprintf("%+v", v)
			buf.Write([]byte(szLog))
			buf.Flush()
		}
	}
	fnWt(v1)
	n := len(OutLogV)
	for i := 0; i < n; i++ {
		fnWt(<-OutLogV)
	}
	fnWt = nil
}

// 日志写入异步队列
func writeoutput(v interface{}) {
	OutLogV <- v
}

func init() {
	RegInitFunc(func() {
		OutLogV = make(chan interface{}, 500)
	})
}
