package masscan

import (
	"bytes"
	"encoding/xml"
	_ "github.com/codegangsta/inject"
	"github.com/hktalent/scan4all/lib/util"
	"io"
	"log"
	"regexp"
)

// 地址
type Address struct {
	Addr     string `xml:"addr,attr" json:"addr" gorm:"primaryKey;"`
	AddrType string `xml:"addrtype,attr" json:"addr_type"`
}

// 状态
type State struct {
	State     string `xml:"state,attr" json:"state"`
	Reason    string `xml:"reason,attr" json:"reason"`
	ReasonTTL string `xml:"reason_ttl,attr" json:"reason_ttl"`
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
	Address Address `json:"address" xml:"address" gorm:"embedded;"`
	// association_autoupdate:true;association_autocreate:true;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;
	Ports []Ports `json:"ports" xml:"ports>port" gorm:"foreignKey:addr;References:addr;"` // association_autocreate:true; // many2many:Host_Ports;foreignKey:ID;References:ID;
}

// `xml:",innerxml"`
//func (cm Host) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
//	if cm.Address != nil {
//		err := e.EncodeToken(cm.comment)
//		if err != nil {
//			return err
//		}
//	}
//	return e.Encode(cm.Member)
//}

// 端口信息
type Ports struct {
	Addr     string  `json:"addr" gorm:"unique_index:addr,protocol,port_id"`
	Protocol string  `xml:"protocol,attr" json:"protocol"`
	PortId   string  `xml:"portid,attr" json:"port_id"`
	State    State   `json:"state" xml:"state" gorm:"embedded;"`
	Service  Service `json:"service" xml:"service"  gorm:"embedded;"`
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
			//log.Printf("%+v\n", i)
			if 0 < len(i.Ports) {
				for _, x9 := range i.Ports {
					x9.Addr = i.Address.Addr
				}
				nR := util.UpInsert[Host](&i, "addr=?", i.Address.Addr)
				if 1 > nR {
					log.Println("util.UpInsert fail \n", line)
				}
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
				//host.Ip = host.Address.Addr
				hosts = append(hosts, host)
			}
		default:
		}
	}
	return hosts, nil
}
