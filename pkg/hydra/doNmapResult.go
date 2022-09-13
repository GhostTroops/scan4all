package hydra

import (
	"bytes"
	"fmt"
	"github.com/antchfx/xmlquery"
	"github.com/hktalent/scan4all/lib/util"
	"github.com/hktalent/scan4all/pkg"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
)

// 弱口令检测
func CheckWeakPassword(ip, service string, port int) {
	util.DoSyncFunc(func() {
		// 在弱口令检测范围就开始检测，结果....
		service = strings.ToLower(service)
		if pkg.Contains(ProtocolList, service) {
			//log.Println("start CheckWeakPassword ", ip, ":", port, "(", service, ")")
			Start(ip, port, service)
		}
	})
}

// 开启了es
var enableEsSv, bCheckWeakPassword bool = false, true

func init() {
	util.RegInitFunc(func() {
		enableEsSv = util.GetValAsBool("enableEsSv")
		bCheckWeakPassword = util.GetValAsBool("CheckWeakPassword")
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

func DoParseXml(s string, bf *bytes.Buffer) {
	doc, err := xmlquery.Parse(strings.NewReader(s))
	if err != nil {
		log.Println("DoParseXml： ", err)
		return
	}

	m1 := make(map[string][][]string)
	for _, n := range xmlquery.Find(doc, "//host") {
		x1 := n.SelectElement("address").Attr[0].Value
		ps := n.SelectElements("ports/port")
		for _, x := range ps {
			if "open" == x.SelectElement("state").Attr[0].Value {
				ip := x1
				szPort := GetAttr(x.Attr, "portid")
				port, _ := strconv.Atoi(szPort)
				service := strings.ToLower(GetAttr(x.SelectElement("service").Attr, "name"))
				//bf.Write([]byte(fmt.Sprintf("%s:%s\n", ip, szPort)))
				szUlr := fmt.Sprintf("http://%s:%s\n", ip, szPort)
				bf.Write([]byte(szUlr))
				if bCheckWeakPassword {
					CheckWeakPassword(ip, service, port)
				} else {
					log.Println("bCheckWeakPassword = ", bCheckWeakPassword)
				}
				// 存储结果到其他地方
				//x9 := AuthInfo{IPAddr: ip, Port: port, Protocol: service}
				// 构造发送es等数据
				if enableEsSv {
					var xx09 = [][]string{}
					if a1, ok := m1[ip]; ok {
						xx09 = a1
					}
					m1[ip] = append(xx09, []string{szPort, service})
				}
				if os.Getenv("NoPOC") != "true" {
					if "socks5" == service || "vnc" == service {
						CheckWeakPassword(ip, service, port)
					} else if "445" == szPort && service == "microsoft-ds" || "135" == szPort && service == "msrpc" {
						util.PocCheck_pipe <- &util.PocCheck{
							Wappalyzertechnologies: &[]string{service},
							URL:                    szUlr,
							FinalURL:               szUlr,
							Checklog4j:             false,
						}
					} else if "8291" == szPort { // CVE_2018_14847
						util.PocCheck_pipe <- &util.PocCheck{
							Wappalyzertechnologies: &[]string{"RouterOS"},
							URL:                    szUlr,
							FinalURL:               szUlr,
							Checklog4j:             false,
						}
					} else if bCheckWeakPassword && "110" == szPort && service == "pop3" {
						CheckWeakPassword(ip, service, port)
					} else if "2181" == szPort {
						util.PocCheck_pipe <- &util.PocCheck{
							Wappalyzertechnologies: &[]string{"ZookeeperUnauthority"},
							URL:                    szUlr,
							FinalURL:               szUlr,
							Checklog4j:             false,
						}
					}
				}
				if bCheckWeakPassword {
					if "8728" == szPort && service == "unknown" {
						CheckWeakPassword(ip, "router", port)
					} else if ("5985" == szPort || "5986" == szPort) && -1 < strings.Index(service, "microsoft ") {
						CheckWeakPassword(ip, "winrm", port)
					}
				}

				log.Printf("%s\t%d\t%s\n", ip, port, service)
			}
		}
	}
	if enableEsSv {
		if 0 < len(m1) {
			for k, x := range m1 {
				util.SendAData[[]string](k, x, util.Nmap)
			}
		}
	}
}

// 处理使用者自己扫描的结果
func DoNmapWithFile(s string, bf *bytes.Buffer) bool {
	if strings.HasSuffix(strings.ToLower(s), ".xml") {
		util.DoSyncFunc(func() {
			b, err := ioutil.ReadFile(s)
			if nil == err && 0 < len(b) {
				DoParseXml(string(b), bf)
			} else {
				log.Println("DoNmapWithFile: ", err)
			}
		})
		return true
	}
	return false
}

// 处理 naabu 端口扫描环节的结果文件
func DoNmapRst(bf *bytes.Buffer) {
	if x1, ok := util.TmpFile[string(util.Naabu)]; ok {
		for _, x := range x1 {
			defer func(r *os.File) {
				r.Close()
				os.RemoveAll(r.Name())
			}(x)
			b, err := ioutil.ReadFile(x.Name())
			if nil == err && 0 < len(b) {
				//fmt.Println("read nmap xml file ok: ", len(b))
				DoParseXml(string(b), bf)
			} else {
				log.Println("ioutil.ReadFile(x.Name()): ", err)
			}
		}
	} else {
		log.Println("check weak passwd: not find nmap tmp*.xml file")
	}
}
