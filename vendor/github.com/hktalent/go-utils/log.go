package go_utils

import (
	"fmt"
	"log"
	"os"
	"strings"
)

var NoColor bool

// out filename
var Output = ""

//// 调用方法名作为插件名
//func GetPluginName(defaultVal string) string {
//	pc, _, _, ok := runtime.Caller(1)
//	details := runtime.FuncForPC(pc)
//	if ok && details != nil {
//		return details.Name()
//	}
//	return defaultVal
//}

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

func Writeoutput(v interface{}) {
	if 1 > len(Output) {
		return
	}
	szLog := fmt.Sprintf("%+v", v)
	f, err := os.OpenFile(Output, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Could not create output fiale '%s': %s\n", Output, err)
		return
	}
	defer f.Close() //nolint
	f.WriteString(szLog)
}
