package util

import (
	Const "github.com/hktalent/go-utils"
	util "github.com/hktalent/go-utils"
	"github.com/projectdiscovery/goflags"
	"math"
	"strings"
)

type Options struct {
	Target         string `json:"target"` // scan target
	ScanType       string `json:"scan_type"`
	ExcludeIps     string `json:"exclude_ips"`      // 排除的ip
	ExcludeIpsFile string `json:"exclude_ips_file"` // 排除的文件
	Ports          string `json:"ports"`            // 文件时，自动合并多行为扫描目标
	TopPorts       string `json:"top_ports"`        // 动态调用nmap来获取
	ExcludePorts   string `json:"exclude_ports"`    // 支持文件名的格式
	Output         string `json:"output"`
	JSON           bool   `json:"json"`
	CSV            bool   `json:"csv"`
	Debug          bool   `json:"debug"`
	Update         bool   `json:"update"`
}

// 默认扫描类型
var DefaultScan uint64 = Const.ScanType_SSLInfo | Const.ScanType_SubDomain | Const.ScanType_WeakPassword | Const.ScanType_Masscan | Const.ScanType_Nmap | Const.ScanType_IpInfo | Const.ScanType_GoPoc | Const.ScanType_WebFingerprints | Const.ScanType_WebInfo | Const.ScanType_WebVulsScan | Const.ScanType_WebDirScan | Const.ScanType_Httpx | Const.ScanType_DNSx | Const.ScanType_Uncover | Const.ScanType_Ffuf | Const.ScanType_Subfinder | Const.ScanType_Shuffledns | Const.ScanType_Tlsx | Const.ScanType_Nuclei | Const.ScanType_Gobuster | Const.ScanType_SubDomain | Const.ScanType_Wappalyzer

// 新版本解析参数
func ParseOptions() *Options {
	flagSet := goflags.NewFlagSet()
	var options = &Options{}
	flagSet.SetDescription(`scan4all is ` + util.Version)
	flagSet.CreateGroup("input", "scan target input",
		flagSet.StringVarP(&options.Target, "target", "l", "", "scan target lists：dir; file format:xml(nmap、masscan)、txt(lists); url、ip、domain、cidrs\n1、ip/cidrs default："+strings.Join(Const.GetTypeNames(Const.ScanType_Ips), ",")+"\n2、url default: "+strings.Join(Const.GetTypeNames(Const.ScanType_Webs), ",")+"\n3、*.domain default: "+strings.Join(Const.GetTypeNames(Const.ScanType_SubDomain), ",")),
		flagSet.StringVarP(&options.Target, "host", "u", "", "scan target：dir; url、ip、domain、cidrs"),
		flagSet.StringVarP(&options.ScanType, "scanType", "s", strings.Join(Const.GetTypeNames(DefaultScan), ","), "all scan type: "+strings.Join(Const.GetTypeNames(math.MaxUint64), ",")),
		//flagSet.StringVarP(&options.ExcludeIps, "eh", "exclude-hosts", "", "hosts to exclude from the scan (comma-separated)"),
		//flagSet.StringVarP(&options.ExcludeIpsFile, "ef", "exclude-file", "", "list of hosts to exclude from scan (file)"),
	)

	flagSet.CreateGroup("port", "Port",
		flagSet.StringVarP(&options.Ports, "p", "port", "", "ports to scan (80,443, 100-200"),
		flagSet.StringVarP(&options.TopPorts, "tp", "top-ports", "1000", "top ports to scan (default 100)"),
		flagSet.StringVarP(&options.ExcludePorts, "ep", "exclude-ports", "", "ports to exclude from scan (comma-separated)"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.Output, "output", "o", "", "file to write output to (optional)"),
		flagSet.BoolVar(&options.JSON, "json", false, "write output in JSON lines format"),
		flagSet.BoolVar(&options.CSV, "csv", false, "write output in csv format"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&options.Debug, "debug", false, "display debugging information"),
		flagSet.BoolVarP(&options.Debug, "verbose", "v", false, "display verbose information"),
	)
	flagSet.CreateGroup("config", "Config",
		flagSet.BoolVar(&options.Update, "update", false, "update to latest"),
	)

	_ = flagSet.Parse()
	return options
}
