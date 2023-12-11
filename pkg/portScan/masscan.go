package portScan

import (
	"bytes"
	"encoding/xml"
	"github.com/GhostTroops/scan4all/lib/goSqlite_gorm/pkg/models"
	"github.com/GhostTroops/scan4all/lib/util"
	_ "github.com/codegangsta/inject"
	"io"
	"log"
	"os/exec"
	"time"
)

type PortsStr string
type TargetStr string
type RangesStr string
type RateStr string
type ExcludeStr string
type SystemPathStr string

// masscan 参数
type Masscan struct {
	SystemPath SystemPathStr `inject` // 系统目录
	Args       []string      `inject` // 参数
	Ports      PortsStr      `inject` // 端口
	Target     TargetStr     `inject` // 目标
	Ranges     RangesStr     `inject` // 范围
	Rate       RateStr       `inject` // 速率
	Exclude    ExcludeStr    `inject` // 排除，执行过的，加入排除列表
	Evt        *models.EventData
}

func New() *Masscan {
	return &Masscan{}
}

func (m *Masscan) SetSystemPath(systemPath string) {
	if systemPath != "" {
		m.SystemPath = SystemPathStr(systemPath)
	}
}
func (m *Masscan) SetArgs(arg ...string) {
	m.Args = arg
}

func (m *Masscan) SetRate(rate string) {
	m.Rate = RateStr(rate)
}

// masscan -p- --rate=2000 192.168.10.31
func (m *Masscan) Run(fnCbk func(*models.Host)) error {
	//var outb, errs bytes.Buffer
	if m.Rate != "" {
		m.Args = append(m.Args, "--rate")
		m.Args = append(m.Args, string(m.Rate))
	}
	if m.Ports != "" {
		m.Args = append(m.Args, "-p")
		m.Args = append(m.Args, string(m.Ports))
	}
	if m.Ranges != "" {
		m.Args = append(m.Args, "--range")
		m.Args = append(m.Args, string(m.Ranges))
	}
	// 输出到 控制台 xml格式
	m.Args = append(m.Args, "-oX")
	m.Args = append(m.Args, "-")
	if m.Target != "" {
		m.Args = append(m.Args, string(m.Target))
	}
	if m.SystemPath == "" {
		s01, err := exec.LookPath("masscan")
		if err != nil {
			log.Println("exec.LookPath ", err)
		} else {
			m.SystemPath = SystemPathStr(s01)
		}
	}
	err := util.AsynCmd(func(line string) {
		x1, err := m.ParseLine(line)
		if nil != err {
			//log.Println(err)
			return
		}
		for _, i := range x1 {
			//log.Printf("%+v\n", i)
			if 0 < len(i.Ports) {
				for _, x9 := range i.Ports {
					x9.Addr = i.Address.Addr
				}
				fnCbk(&i)
				//nR := util.UpInsert[models.Host](&i, "addr=?", i.Address.Addr)
				//if 1 > nR {
				//	log.Println("util.UpInsert fail \n", line)
				//}
			}
		}
	}, string(m.SystemPath), m.Args...)
	return err
}

// parse line
func (m *Masscan) ParseLine(s string) ([]models.Host, error) {
	decoder := xml.NewDecoder(bytes.NewReader([]byte(s)))
	var hosts []models.Host
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
				var host models.Host
				err := decoder.DecodeElement(&host, &a)
				if err == io.EOF || err != nil {
					break
				}
				//host.Ip = host.Address.Addr
				hosts = append(hosts, host)
			}
		default:
			time.Sleep(33 * time.Second)
		}
	}
	return hosts, nil
}
