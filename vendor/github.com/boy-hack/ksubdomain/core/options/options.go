package options

import (
	"fmt"
	"github.com/boy-hack/ksubdomain/core"
	"github.com/boy-hack/ksubdomain/core/device"
	"github.com/boy-hack/ksubdomain/core/gologger"
	"github.com/boy-hack/ksubdomain/runner/outputter"
	"github.com/boy-hack/ksubdomain/runner/processbar"
	"github.com/google/gopacket/layers"
	"strconv"
	"strings"
)

type Options struct {
	Rate             int64              // 每秒发包速率
	Domain           chan string        // 域名输入
	DomainTotal      int                // 扫描域名总数
	Resolvers        []string           // dns resolvers
	Silent           bool               // 安静模式
	TimeOut          int                // 超时时间 单位(秒)
	Retry            int                // 最大重试次数
	Method           string             // verify模式 enum模式 test模式
	DnsType          string             // dns类型 a ns aaaa
	Writer           []outputter.Output // 输出结构
	ProcessBar       processbar.ProcessBar
	EtherInfo        *device.EtherTable  // 网卡信息
	SpecialResolvers map[string][]string // 可针对特定域名使用的dns resolvers
}

func Band2Rate(bandWith string) int64 {
	suffix := string(bandWith[len(bandWith)-1])
	rate, _ := strconv.ParseInt(string(bandWith[0:len(bandWith)-1]), 10, 64)
	switch suffix {
	case "G":
		fallthrough
	case "g":
		rate *= 1000000000
	case "M":
		fallthrough
	case "m":
		rate *= 1000000
	case "K":
		fallthrough
	case "k":
		rate *= 1000
	default:
		gologger.Fatalf("unknown bandwith suffix '%s' (supported suffixes are G,M and K)\n", suffix)
	}
	packSize := int64(80) // 一个DNS包大概有74byte
	rate = rate / packSize
	return rate
}
func GetResolvers(resolvers string) []string {
	// handle resolver
	var rs []string
	var err error
	if resolvers != "" {
		rs, err = core.LinesInFile(resolvers)
		if err != nil {
			gologger.Fatalf("读取resolvers文件失败:%s\n", err.Error())
		}
		if len(rs) == 0 {
			gologger.Fatalf("resolvers文件内容为空\n")
		}
	} else {
		defaultDns := []string{
			"223.5.5.5",
			"223.6.6.6",
			//"180.76.76.76",
			"119.29.29.29",
			"182.254.116.116",
			"114.114.114.115",
		}
		rs = defaultDns
	}
	return rs
}
func (opt *Options) Check() {

	if opt.Silent {
		gologger.MaxLevel = gologger.Silent
	}

	core.ShowBanner()

}
func DnsType(s string) (layers.DNSType, error) {
	s = strings.ToLower(s)
	switch s {
	case "a":
		return layers.DNSTypeA, nil
	case "ns":
		return layers.DNSTypeNS, nil
	case "cname":
		return layers.DNSTypeCNAME, nil
	case "txt":
		return layers.DNSTypeTXT, nil
	case "aaaa":
		return layers.DNSTypeAAAA, nil
	case "uri":
		return layers.DNSTypeURI, nil
	default:
		return layers.DNSTypeA, fmt.Errorf("无法将%s转换为DNSType类型", s)
	}
}
func GetDeviceConfig() *device.EtherTable {
	filename := "ksubdomain.yaml"
	var ether *device.EtherTable
	var err error
	if core.FileExists(filename) {
		ether, err = device.ReadConfig(filename)
		if err != nil {
			gologger.Fatalf("读取配置失败:%v", err)
		}
		gologger.Infof("读取配置%s成功!\n", filename)
	} else {
		ether = device.AutoGetDevices()
		err = ether.SaveConfig(filename)
		if err != nil {
			gologger.Fatalf("保存配置失败:%v", err)
		}
	}
	gologger.Infof("Use Device: %s\n", ether.Device)
	gologger.Infof("Use IP:%s\n", ether.SrcIp.String())
	gologger.Infof("Local Mac: %s\n", ether.SrcMac.String())
	gologger.Infof("GateWay Mac: %s\n", ether.DstMac.String())
	return ether
}
