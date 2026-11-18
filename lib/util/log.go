package util

import (
	"encoding/json"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/goSqlite_gorm/pkg/models"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
)

const Scan4all = "scan4all"

// out filename
var Output = ""

// // 调用方法名作为插件名
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
	Writeoutput(v)
}

func GetEsType(s int64) ESaveType {
	return Scan4all
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
			SendAnyData(v, GetEsType(nCurType))
			Writeoutput(v)
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
		Writeoutput(v)
	}
}

// writeMu 保证多协程并发写同一输出文件时记录不交错
var writeMu sync.Mutex

func Writeoutput(v interface{}) {
	if 1 > len(Output) {
		return
	}
	var szLog string
	if strings.HasSuffix(Output, ".csv") {
		data, _ := json.Marshal(v)
		szLog = string(data) + "\n"
	} else {
		szLog = fmt.Sprintf("%+v\n", v)
	}
	writeMu.Lock()
	defer writeMu.Unlock()
	f, err := os.OpenFile(Output, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Could not create output fiale '%s': %s\n", Output, err)
		return
	}
	defer f.Close() //nolint
	if _, err = f.WriteString(szLog); nil != err {
		log.Printf("write output '%s' error: %s\n", Output, err)
	}
}

// logOnceMap 用于 LogOnce 的 key 去重
var logOnceMap sync.Map

// LogOnce 相同 key 的日志只输出一次，避免批量扫描时同类错误刷屏。
// msg 为已格式化好的文本，调用方自行使用 fmt.Sprintf 拼装，避免 printf 包装歧义。
func LogOnce(key string, msg string) {
	if _, loaded := logOnceMap.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	log.Print(msg)
}
