package util

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"os"
	"strings"
)

var NoColor bool
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
	writeoutput(fmt.Sprintf("%+v", v))
}

func writeoutput(log string) {
	if "" == Output {
		return
	}
	f, err := os.OpenFile(Output, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		gologger.Fatal().Msgf("Could not create output fiale '%s': %s\n", Output, err)
	}
	defer f.Close() //nolint
	f.WriteString(log)
}
