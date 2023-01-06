package util

import (
	"bytes"
	"github.com/hktalent/51pwnPlatform/pkg/models"
	Const "github.com/hktalent/go-utils"
	"github.com/projectdiscovery/iputil"
	"os"
	"strings"
)

const (
	HttpPre  = "http://"
	HttpsPre = "https://"
)

type ScanTarget struct {
	RawTarget string   `json:"raw_target"` // 单目标原始输入，url（拆解为domain）、ip、domain、cidrs
	Domain    []string `json:"domain"`     // 原始输入拆解后的domain
	Ips       []string `json:"ips"`        // 目标分解后的ip列表，包含domain 定位后的ip信息
}

/*
解析、处理目标
输入格式：xml（nmap、masscan）、txt（lists）
单目标：url（拆解为domain）、ip、domain、cidrs
*/
func DoInput(s string, bf *bytes.Buffer) {
	if FileExists(s) {
		if data, err := os.ReadFile(s); nil == err {
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
		oT.EventType = int64(Const.ScanType_Ips)
	} else {
		s1 := strings.ToLower(strings.TrimSpace(s))
		if strings.HasPrefix(s1, HttpPre) || strings.HasPrefix(s1, HttpsPre) { // url
			oT.EventType = int64(Const.ScanType_Webs)
		} else if strings.HasPrefix(s1, "*.") { // domain
			oT.EventType = int64(Const.ScanType_Subfinder | Const.ScanType_SubDomain)
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
