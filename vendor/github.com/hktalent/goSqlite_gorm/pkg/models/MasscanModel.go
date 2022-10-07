package models

import (
	"encoding/xml"
	"github.com/asaskevich/govalidator"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"log"
	"net/url"
	"regexp"
)

// 扫描目标，非存储，chan时用
type Target4Chan struct {
	TaskId     string `json:"task_id"`     // 任务id
	ScanWeb    string `json:"scan_web"`    // base64解码后
	ScanType   int64  `json:"scan_type"`   // 扫描类型
	ScanConfig string `json:"scan_config"` // 本次任务的若干细节配置，json格式的string
}

// 地址
type Address struct {
	Addr     string `xml:"addr,attr" json:"addr" gorm:"primaryKey;type:varchar(60)"`
	AddrType string `xml:"addrtype,attr" json:"addr_type" gorm:"type:varchar(20)"`
}

// 状态
type State struct {
	State     string `xml:"state,attr" json:"state" gorm:"type:varchar(20)"`
	Reason    string `xml:"reason,attr" json:"reason" gorm:"type:varchar(20)"`
	ReasonTTL string `xml:"reason_ttl,attr" json:"reason_ttl" gorm:"type:varchar(20)"`
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
	Ports []Ports `json:"Ports" xml:"Ports>port" gorm:"foreignKey:addr;References:addr;"` // association_autocreate:true; // many2many:Host_Ports;foreignKey:ID;References:ID;
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
	Addr     string  `json:"addr" gorm:"type:varchar(60);unique_index:addr,protocol,port_id"`
	Protocol string  `xml:"protocol,attr" json:"protocol" gorm:"type:varchar(10);"`
	PortId   string  `xml:"portid,attr" json:"port_id"  gorm:"type:varchar(10);"`
	State    State   `json:"state" xml:"state" gorm:"embedded;"`
	Service  Service `json:"service" xml:"service"  gorm:"embedded;"`
}

// 服务信息
type Service struct {
	Name   string `xml:"name,attr" json:"name"  gorm:"type:varchar(20);"`
	Banner string `xml:"banner,attr" json:"banner"  gorm:"type:varchar(800);"`
}

// 事件数据
type EventData struct {
	EventType int64         // 类型：masscan、nmap
	EventData []interface{} // func，parms
	Task      *Target4Chan  // 当前task任务数据
	//Ips            []string                                         // 当前任务相关的ip
	//SubDomains2Ips *map[string]map[string]map[int]map[string]string // 所有子域名 -> ip ->port -> port info
}

var (
	dnsclient *dnsx.DNSX
)

func init() {
	dnsOptions := dnsx.DefaultOptions
	dnsOptions.MaxRetries = 3
	dnsOptions.Hostsfile = true
	var err error
	dnsclient, err = dnsx.New(dnsOptions)
	if nil != err {
		log.Println("dnsx.New(dnsOptions) ", err)
	}
}

// 目标：url、dns（域名）、ip
//  转换、输出ip
func (r *EventData) Target2Ip() []string {
	var a []string
	t := r.Task.ScanWeb
	if govalidator.IsCIDR(t) {
		a = append(a, t)
	} else if govalidator.IsIP(t) {
		a = append(a, t)
	} else if govalidator.IsDNSName(t) {
		if nil != dnsclient {
			if ips, err := dnsclient.Lookup(t); nil == err {
				a = append(a, ips...)
			}
		}
	} else if govalidator.IsURL(t) {
		if oU1, err := url.Parse(r.Task.ScanWeb); nil == err && nil != oU1 {
			t = oU1.Hostname()
			if "" == t {
				t = r.Task.ScanWeb
			}
			if nil != dnsclient {
				if ips, err := dnsclient.Lookup(t); nil == err {
					a = append(a, ips...)
				}
			}
		}
	}

	return a
}

// 获取ip的正则表达式
var GetIpPort = regexp.MustCompile("Discovered open port (\\d+)\\/tcp on ((\\d+\\.){3}\\d+)")
var GetBanner = regexp.MustCompile("Banner on port (\\d+)/tcp on ((\\d+\\.){3}\\d+): \\[([^\\]]+)\\] ([^\\ ]+)( ([^=]+)=((\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})|[^ ]+))*")
