package masscan

import (
	"bytes"
	"encoding/xml"
	_ "github.com/codegangsta/inject"
	"github.com/hktalent/scan4all/lib/util"
	"gorm.io/gorm"
	"io"
	"log"
	"regexp"
)

// 地址
type Address struct {
	Addr     string `xml:"addr,attr" json:"addr"`
	AddrType string `xml:"addrtype,attr" json:"addrType"`
}

// 状态
type State struct {
	State     string `xml:"state,attr" json:"state"`
	Reason    string `xml:"reason,attr" json:"reason"`
	ReasonTTL string `xml:"reason_ttl,attr" json:"reasonTTL"`
}

// nmap 模式
type Nmaprun struct {
	XMLName    xml.Name `xml:"nmaprun"`
	StartTime  string   `xml:"start,attr"`
	Scanner    string   `xml:"scanner,attr"`
	Version    string   `xml:"version,attr"`
	XmlVersion string   `xml:"xmloutputversion,attr"`
}

// 主机信息
//  foreignKey should name the model-local key field that joins to the foreign entity.
//  references should name the foreign entity's primary or unique key.
type Host struct {
	gorm.Model
	//StartTime       string
	//Endtime         string  `xml:"endtime,attr"`
	Ip      string  `json:"-"`
	Port    string  `json:"-"`
	Address Address `json:",inline" xml:"address" gorm:"foreignKey:Ip;references:Addr"`
	Ports   Ports   `json:"ports" xml:"ports>port" gorm:"foreignKey:Port;references:Portid"`
	//LastScanTime    int     `json:"lastScanTime"`
	//LastScanEndTime int     `json:"lastScanEndTime"`
}

// 端口信息
type Ports []struct {
	Protocol string  `xml:"protocol,attr" json:"protocol"`
	Portid   string  `xml:"portid,attr" json:"portid"`
	State1   string  `json:"-"`
	State    State   `json:",inline" xml:"state"  gorm:"foreignKey:State1;references:State"`
	Name     string  `json:"-"`
	Service  Service `json:",inline" xml:"service" gorm:"foreignKey:Name;references:Name"`
}

// 服务信息
type Service struct {
	Name   string `xml:"name,attr" json:"name"`
	Banner string `xml:"banner,attr" json:"banner"`
}

// masscan 参数
type Masscan struct {
	SystemPath string   // 系统目录
	Args       []string // 参数
	Ports      string   // 端口
	Target     string   // 目标
	Ranges     string   // 范围
	Rate       string   // 速率
	Exclude    string   // 排除，执行过的，加入排除列表
}

func New() *Masscan {
	return &Masscan{SystemPath: "masscan"}
}

func (m *Masscan) SetSystemPath(systemPath string) {
	if systemPath != "" {
		m.SystemPath = systemPath
	}
}
func (m *Masscan) SetArgs(arg ...string) {
	m.Args = arg
}

func (m *Masscan) SetRate(rate string) {
	m.Rate = rate
}

// 获取ip的正则表达式
var GetIpPort = regexp.MustCompile("Discovered open port (\\d+)\\/tcp on ((\\d+\\.){3}\\d+)")
var GetBanner = regexp.MustCompile("Banner on port (\\d+)/tcp on ((\\d+\\.){3}\\d+): \\[([^\\]]+)\\] ([^\\ ]+)( ([^=]+)=((\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})|[^ ]+))*")

// masscan -p- --rate=2000 192.168.10.31
func (m *Masscan) Run() error {
	//var outb, errs bytes.Buffer
	if m.Rate != "" {
		m.Args = append(m.Args, "--rate")
		m.Args = append(m.Args, m.Rate)
	}
	if m.Ports != "" {
		m.Args = append(m.Args, "-p")
		m.Args = append(m.Args, m.Ports)
	}
	if m.Ranges != "" {
		m.Args = append(m.Args, "--range")
		m.Args = append(m.Args, m.Ranges)
	}
	// 输出到 控制台 xml格式
	m.Args = append(m.Args, "-oX")
	m.Args = append(m.Args, "-")
	if m.Target != "" {
		m.Args = append(m.Args, m.Target)
	}
	util.AsynCmd(func(line string) {
		x1, err := m.ParseLine(line)
		if nil != err {
			log.Println(err)
			return
		}
		for _, i := range x1 {
			nR := util.UpInsert[Host](&i, "address=? and ports=?", i.Address, i.Ports)
			if 1 >= nR {
				log.Println("util.UpInsert fail")
			}
		}
	}, m.SystemPath, m.Args...)
	return nil
}

// parse line
func (m *Masscan) ParseLine(s string) ([]Host, error) {
	decoder := xml.NewDecoder(bytes.NewReader([]byte(s)))
	var hosts []Host
	for {
		t1, err := decoder.Token()
		if err == io.EOF || t1 == nil {
			break
		}
		if err != nil {
			return nil, err
		}
		switch a := t1.(type) {
		case xml.StartElement:
			if a.Name.Local == "host" {
				var host Host
				err := decoder.DecodeElement(&host, &a)
				if err == io.EOF || err != nil {
					break
				}
				hosts = append(hosts, host)
			}
		default:
		}
	}
	return hosts, nil
}
