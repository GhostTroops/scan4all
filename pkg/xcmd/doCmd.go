package xcmd

import (
	"fmt"
	util "github.com/hktalent/go-utils"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"strings"
)

func GetOsName() string {
	currentOS := "linux"
	switch runtime.GOOS {
	case "darwin":
		currentOS = "macOS"
	default:
		currentOS = runtime.GOOS
	}
	return currentOS
}

// 执行命令、返回结果
//  命令最后一个参数是结果文件名
func DoAsyncCmd(szCmd string, a ...string) string {
	szName := a[len(a)-1]
	currentOS := GetOsName()
	a = append([]string{fmt.Sprintf("tools%c%s%c%s", os.PathSeparator, currentOS, os.PathSeparator, szCmd)}, a...)
	log.Println(strings.Join(a, " "))
	if _, err := DoCmd(a...); nil != err {
		log.Println(err)
	}
	if data, err := ioutil.ReadFile(szName); nil == err && 0 < len(data) {
		return string(data)
	} else {
		log.Println(err)
	}
	return ""
}

func doTpCmd(t, i, o string) string {
	return doTpCmdN(t, i, o, 1)
}
func doTpCmdN(t, i, o string, n int) string {
	a := GetCmdParms(t)
	a = DoParms(a...)
	a[n] = i
	a[len(a)-1] = o
	szRst := DoAsyncCmd(t, a...)
	if util.FileExists(o) {
		os.Remove(o)
	}
	return szRst
}
