package pkg

import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"os"
	"runtime"
	"strings"
)

var NoColor bool
var Output = ""

// log message，Easy to send to ES result server
type LogMsg struct {
	Url        string `json:"url"`
	PluginName string `json:"pluginName"`
	StatusCode int    `json:"statusCode"`
	CheckRst   string `json:"checkRst"`
}

// 调用方法名作为插件名
func GetPluginName(defaultVal string) string {
	pc, _, _, ok := runtime.Caller(1)
	details := runtime.FuncForPC(pc)
	if ok && details != nil {
		return details.Name()
	}
	return defaultVal
}

func LogJson(logMsg LogMsg) {
	spew.Printf("%v", logMsg)
}

func GoPocLog(log string) {
	builder := &strings.Builder{}
	builder.WriteString("[")
	if !NoColor {
		builder.WriteString(aurora.BrightRed("GoPOC").String())
	} else {
		builder.WriteString("GoPOC")
	}
	builder.WriteString("] ")
	builder.WriteString(log)
	fmt.Print(builder.String())
	if Output != "" {
		writeoutput(builder.String())
	}
}

func YmlPocLog(log string) {
	builder := &strings.Builder{}
	builder.WriteString("[")
	if !NoColor {
		builder.WriteString(aurora.BrightRed("YmlPOC").String())
	} else {
		builder.WriteString("YmlPOC")
	}
	builder.WriteString("] ")
	builder.WriteString(log)
	fmt.Print(builder.String())
	if Output != "" {
		writeoutput(builder.String())
	}
}

func BurteLog(log string) {
	builder := &strings.Builder{}
	builder.WriteString("[")
	if !NoColor {
		builder.WriteString(aurora.BrightRed("Brute").String())
	} else {
		builder.WriteString("Brute")
	}
	builder.WriteString("] ")
	builder.WriteString(log)
	fmt.Print(builder.String())
	if Output != "" {
		writeoutput(builder.String())
	}
}

func writeoutput(log string) {
	f, err := os.OpenFile(Output, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		gologger.Fatal().Msgf("Could not create output fiale '%s': %s\n", Output, err)
	}
	defer f.Close() //nolint
	f.WriteString(log)
}
