package util

import (
	"fmt"
	"github.com/antchfx/xmlquery"
	Const "github.com/hktalent/go-utils"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
)

var (
	Naabu = Const.GetTypeName(Const.ScanType_Naabu)
	Nmap  = Const.GetTypeName(Const.ScanType_Nmap)
)

// 弱口令检测
func CheckWeakPassword(ip, service string, port int) {
	if !bCheckWeakPassword {
		return
	}
	// 在弱口令检测范围就开始检测，结果....
	service = strings.ToLower(service)
	SendEvent(&Const.EventData{
		EventType: Const.ScanType_WeakPassword,
		EventData: []interface{}{ip, port, service},
	}, Const.ScanType_WeakPassword)
}

// 开启了es
var bCheckWeakPassword bool = true

func init() {
	RegInitFunc(func() {
		EnableEsSv = GetValAsBool("EnableEsSv")
		bCheckWeakPassword = GetValAsBool("CheckWeakPassword")
		//log.Println("CheckWeakPassword = ", util.GetVal("CheckWeakPassword"), " bCheckWeakPassword = ", bCheckWeakPassword)
	})
}

func GetAttr(att []xmlquery.Attr, name string) string {
	for _, x := range att {
		if x.Name.Local == name {
			return x.Value
		}
	}
	return ""
}

// 解析 nmap、masscan 输出的xml结果
//
//	解析的结果保存到 bf 中
//	解析的同时：
//	  1、触发端口弱口令检测，如果当前任务不需要，则，弱口令检测的入口处拦截、过滤
//	  2、端口 POC 检测，如果当前任务不需要，则，弱口令检测的入口处拦截、过滤
func DoParseXml(s string, taskT uint64) {
	doc, err := xmlquery.Parse(strings.NewReader(s))
	if err != nil {
		log.Println("DoParseXml： ", err)
		return
	}

	m1 := make(map[string][][]string)
	for _, n := range xmlquery.Find(doc, "//host") {
		hostName := n.SelectElements("hostnames/hostname")
		var aDns []string
		for _, x := range hostName {
			aDns = append(aDns, GetAttr(x.Attr, "name"))
		}
		x1 := n.SelectElement("address").Attr[0].Value
		if 0 == len(aDns) {
			aDns = append(aDns, x1)
		}

		ps := n.SelectElements("ports/port")
		for _, x := range ps {
			if "open" == x.SelectElement("state").Attr[0].Value {
				ip := x1
				sz1 := GetAttr(x.Attr, "protocol")
				if "tcp" != sz1 {
					continue
				}
				szPort := GetAttr(x.Attr, "portid")
				port, _ := strconv.Atoi(szPort)
				service := strings.ToLower(GetAttr(x.SelectElement("service").Attr, "name"))
				//bf.Write([]byte(fmt.Sprintf("%s:%s\n", ip, szPort)))

				// 存储结果到其他地方
				//x9 := AuthInfo{IPAddr: ip, Port: port, Protocol: service}
				// 构造发送es等数据
				if EnableEsSv {
					var xx09 = [][]string{}
					if a1, ok := m1[ip]; ok {
						xx09 = a1
					}
					m1[ip] = append(xx09, []string{szPort, service})
				}
				// 这里应当还原域名，否则无法正常访问
				for _, dnsJ := range aDns {
					aszUlr := []string{fmt.Sprintf("https://%s:%s", dnsJ, szPort), fmt.Sprintf("http://%s:%s", dnsJ, szPort)}
					for _, szUlr := range aszUlr {
						SendEvent(&Const.EventData{
							EventType: taskT,
							EventData: []interface{}{szUlr},
						}, taskT)
						if os.Getenv("NoPOC") != "true" {
							if "445" == szPort && service == "microsoft-ds" || "135" == szPort && service == "msrpc" {
								PocCheck_pipe <- &PocCheck{
									Wappalyzertechnologies: &[]string{service},
									URL:                    szUlr,
									FinalURL:               szUlr,
									Checklog4j:             false,
								}
							} else if "8291" == szPort { // RouterOS CVE_2018_14847
								PocCheck_pipe <- &PocCheck{
									Wappalyzertechnologies: &[]string{"RouterOS"},
									URL:                    szUlr,
									FinalURL:               szUlr,
									Checklog4j:             false,
								}
							} else if "2181" == szPort { // Zookeeper Unauthority
								PocCheck_pipe <- &PocCheck{
									Wappalyzertechnologies: &[]string{"ZookeeperUnauthority"},
									URL:                    szUlr,
									FinalURL:               szUlr,
									Checklog4j:             false,
								}
							}
						}
					}
				}
				// 若密码、破解
				if bCheckWeakPassword {
					if "8728" == szPort && service == "unknown" { // router
						CheckWeakPassword(ip, "router", port)
					} else if ("5985" == szPort || "5986" == szPort) && -1 < strings.Index(service, "microsoft ") {
						CheckWeakPassword(ip, "winrm", port)
					} else { // if ("110" == szPort || "995" == szPort) && service == "pop3" || "socks5" == service || "vnc" == service {
						CheckWeakPassword(ip, service, port)
					}
				}

				s1 := fmt.Sprintf("%s\t%d\t%s\n", ip, port, service)
				SendLog(ip, "nmap", s1, "")
				log.Printf("%s", s1)
			}
		}
	}
	if EnableEsSv {
		if 0 < len(m1) {
			for k, x := range m1 {
				SendAData[[]string](k, x, Nmap)
			}
		}
	}
}

// 处理使用者自己扫描的结果
//
//	不能用异步，否则后续流程无法读取 buff
func DoNmapWithFile(s string, taskT uint64) bool {
	if strings.HasSuffix(strings.ToLower(s), ".xml") {
		b, err := ioutil.ReadFile(s)
		if nil == err && 0 < len(b) {
			DoParseXml(string(b), taskT)
		} else {
			log.Println("DoNmapWithFile: ", err)
		}
		return true
	}
	return false
}

// 处理 naabu 端口扫描环节的结果文件
func DoNmapRst(taskT uint64) {
	if x1, ok := TmpFile[string(Naabu)]; ok {
		for _, x := range x1 {
			defer func(r *os.File) {
				r.Close()
				os.RemoveAll(r.Name())
			}(x)
			b, err := ioutil.ReadFile(x.Name())
			if nil == err && 0 < len(b) {
				//fmt.Println("read nmap xml file ok: ", len(b))
				DoParseXml(string(b), taskT)
			} else {
				log.Println("ioutil.ReadFile(x.Name()): ", err)
			}
		}
	} else {
		log.Println("check weak passwd: not find nmap tmp*.xml file")
	}
}
