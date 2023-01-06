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

// 获取系统名
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

// 执行命令前，先查询，如果没有再继续执行
// 剥离 s 中互联网目标，然后查询
func DoQueryIndex(t, s string) interface{} {

	return nil
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
		ss1 := string(data)
		SaveMdRst(ss1, szCmd, a)
		return ss1
	} else {
		log.Println(err)
	}
	return ""
}

// 执行命令 t，输入 i 默认替换 1 位置的参数，o 输出为最后一个参数
func doTpCmd(t, i, o string) string {
	return doTpCmdN(t, i, o, 1)
}

// 执行命令 t，并将输入 i 替换n位置的入参数，o 输出为最后一个参数
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
