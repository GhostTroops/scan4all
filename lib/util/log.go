package util

import (
	"bufio"
	"encoding/csv"
	"fmt"
	Const "github.com/hktalent/go-utils"
	"log"
	"os"
	"runtime"
	"strings"
)

// out filename
var Output = ""

func Logs(a ...any) {
	s := fmt.Sprintf("%v", a[0])
	if -1 < strings.Index(s, "%") {
		log.Printf(s, a[1:]...)
	} else {
		log.Println(a...)
	}
}

// // 调用方法名作为插件名
func GetPluginName(defaultVal string) string {
	pc, _, _, ok := runtime.Caller(1)
	details := runtime.FuncForPC(pc)
	if ok && details != nil {
		return details.Name()
	}
	return defaultVal
}

var Scan4all = Const.GetTypeName(Const.ScanType_Scan4all)

// 1、优化代码，统一结果输出，便于维护
func SendLog(szUrl, szVulType, Msg, Payload string) {
	v := &SimpleVulResult{
		Url:     szUrl,
		VulKind: Scan4all,
		VulType: szVulType,
		Payload: Payload,
		Msg:     strings.TrimSpace(Msg) + " " + szVulType,
	}
	SendAnyData(v, Scan4all)
	writeoutput(v)
}

// 专门发送改造后的引擎函数执行结果
func SendEngineLog(evt *Const.EventData, nCurType uint64, data ...interface{}) {
	if nil != data && 0 < len(data) {
		szT := Scan4all
		v := &SimpleVulResult{
			Url:      evt.Task.ScanWeb,
			VulKind:  szT,
			ScanType: nCurType,
			ScanData: data,
		}
		if s, ok := Const.ScanType2Str[nCurType]; ok {
			szT = s
		}
		SendAnyData(v, szT)
		writeoutput(v)

	}
}

// 专门发送改造后的引擎函数执行结果
func SendEngineLog4Url(Url string, nCurType uint64, data ...interface{}) {
	if nil != data && 0 < len(data) {
		szT := Scan4all
		v := &SimpleVulResult{
			Url:      Url,
			VulKind:  string(szT),
			ScanType: nCurType,
			ScanData: data,
		}
		SendAnyData(v, szT)
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
