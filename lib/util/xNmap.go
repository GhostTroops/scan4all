package util

import (
	"bytes"
	"fmt"
	Const "github.com/hktalent/go-utils"
	"io"
	"io/ioutil"
	"runtime"
	"strings"
)

// 数据转换
func CvtData(d []interface{}) []string {
	var a []string
	for _, x := range d {
		switch x.(type) {
		case string:
			a = append(a, x.(string))
		case []string:
			a = append(a, x.([]string)...)
		case []interface{}:
			a = append(a, CvtData(x.([]interface{}))...)
		default:
			a = append(a, fmt.Sprintf("%v", x))
		}
	}
	return a
}

// 注册Nmap
// nmap -sT --top-ports 1000 -v -oG -
// nmap --top-ports 1000  -v -oG -
// nmap --top-ports 100  -v -oG -
func init() {
	RegInitFunc(func() {
		// 保存数据也采用统一的线程池
		if nil != EngineFuncFactory {
			EngineFuncFactory(Const.ScanType_Nmap, func(evt *Const.EventData, args ...interface{}) {
				if nil != evt && 0 < len(evt.EventData) {
					return
				}
				tempI, err1 := ioutil.TempFile("", "stdin-in-*")
				tempO, err := ioutil.TempFile("", "*.xml")
				if err == nil && err1 == nil {
					defer tempO.Close()
					a10 := CvtData(evt.EventData)
					a10 = append(a10, CvtData(args)...)
					io.Copy(tempI, bytes.NewReader([]byte(strings.Join(a10, "\n"))))
					tempI.Close()
					s009 := "/config/doNmapScan.sh "
					if runtime.GOOS == "windows" {
						s009 = "/config/doNmapScanWin.bat "
					}
					x := SzPwd + s009 + tempI.Name() + " " + tempO.Name()
					if _, err := DoCmd(strings.Split(x, " ")...); nil == err {
						DoNmapWithFile(tempO.Name(), evt.EventType)
					}
				}
			})
		}
	})
}
