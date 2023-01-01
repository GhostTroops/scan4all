package util

import (
	"bytes"
	"github.com/hktalent/51pwnPlatform/pkg/models"
	Const "github.com/hktalent/go-utils"
	"github.com/projectdiscovery/iputil"
	"io/ioutil"
	"strings"
)

const (
	HttpPre  = "http://"
	HttpsPre = "https://"
)

/*
解析、处理目标
str    ip/cidrs,domain（*.*.xxx.com）url
txt
xml nmap
*/
func DoInput(s string, bf *bytes.Buffer) {
	if FileExists(s) {
		if data, err := ioutil.ReadFile(s); nil == err {
			s2 := strings.ToLower(s)
			if strings.HasSuffix(s2, ".txt") {
				a := strings.Split(strings.TrimSpace(string(data)), "\n")
				for _, x := range a {
					func(s1 string) {
						DefaultPool.Submit(func() {
							DoOne(s1)
						})
					}(x)
				}
			} else if strings.HasSuffix(s2, ".xml") {
				if nil == bf {
					bf = &bytes.Buffer{}
				}
				DoNmapWithFile(s2, bf)
			}
		}
	} else { // str
		DoOne(s)
	}
}

/*
  IP / CIDRS: 端口扫描，ssl信息获取，社工（shodan等）获取; -> 弱密码检测
  url ： web指纹、web扫描、弱密码检测、webshell扫描，ssl信息，分解出的 domain 继续走domain任务
*/
func DoOne(s string) {
	s = strings.TrimSpace(s)
	var oT = &models.EventData{EventData: []interface{}{s}}
	if iputil.IsCIDR(s) || iputil.IsIP(s) { // ip/cidrs
		oT.EventType = int64(Const.ScanType_Nmap)
	} else {
		s1 := strings.ToLower(s)
		if strings.HasPrefix(s1, HttpPre) || strings.HasPrefix(s1, HttpsPre) { // url
			oT.EventType = int64(Const.ScanType_Nmap)
		} else if strings.HasPrefix(s1, "*.") { // domain
			oT.EventType = int64(Const.ScanType_Nmap)
		}
	}
	SendEvent(oT, oT.EventType)
}

func init() {
	RegInitFunc(func() {
		EngineFuncFactory(int64(Const.ScanType_Nmap), func(evt *models.EventData, args ...interface{}) {

		})
	})
}
