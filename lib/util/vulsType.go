package util

import (
	. "github.com/hktalent/51pwnPlatform/lib/scan/Const"
	"sync"
)

// curl -s 'https://api.hackertarget.com/aslookup/?q=AS1449'
type ESaveType string

func GetEsType(nType int64) ESaveType {
	if s, ok := MType[nType]; ok {
		return s
	}
	return ESaveType("")
}

var (
	Naabu     ESaveType = GetEsType(ScanType_Naabu)
	Httpx     ESaveType = GetEsType(ScanType_Httpx)
	Hydra     ESaveType = GetEsType(ScanType_Pswd4hydra)
	Nmap      ESaveType = GetEsType(ScanType_Nmap)
	Scan4all  ESaveType = "scan4all"
	Subfinder ESaveType = GetEsType(ScanType_SubDomain)
)

// es 索引类型
var MType = map[int64]ESaveType{
	ScanType_SSLInfo:         "ssl",          // 01- SSL信息分析，并对域名信息进行收集、进入下一步流程
	ScanType_SubDomain:       "subdomain",    // 02- 子域名爆破，新域名回归 到:  1 <-- -> 2，做去重处理
	ScanType_MergeIps:        "ip",           // 03- 默认自动合并ip，记录ip与域名的关联关系，再发送payload时考虑：相同ip不同域名，相同payload分别发送 合并相同目标 若干域名的ip，避免扫描时重复
	ScanType_Pswd4hydra:      "hydra",        // 04- 密码破解，隐含包含了: 端口扫描(05-masscan + 06-nmap)
	ScanType_Masscan:         "nmap",         // 05- 合并后的ip 进行快速端口扫描
	ScanType_Nmap:            "nmap",         // 06、精准 端口指纹，排除masscan已经识别的几种指纹
	ScanType_IpInfo:          "ip",           // 07- 获取ip info
	ScanType_GoPoc:           "vuls",         // 08- go-poc 检测, 隐含包含了: a、filefuzz,b、指纹扫描，c、05-masscan d 06-nmap)
	ScanType_PortsWeb:        "web",          // 09- web端口识别，Naabu,识别 https，识别存活的web端口，再进入下一流程
	ScanType_WebFingerprints: "fingerprints", // 10- web指纹，识别蜜罐，并标识
	ScanType_WebDetectWaf:    "waf",          // 11- detect WAF
	ScanType_WebScrapy:       "scrapy",       // 12- 爬虫分析，form表单识别，字段名识别，form action提取；
	ScanType_WebInfo:         "webinfo",      // 13- server、x-powerby、x***，url、ip、其他敏感信息（姓名、电话、地址、身份证）
	ScanType_WebVulsScan:     "nuclei",       // 14-nuclei
	ScanType_WebDirScan:      "webdir",       // 14-dir爆破,Gobuster,file fuzz
	ScanType_Naabu:           "naabu",        // 15- naabu
	ScanType_Httpx:           "httpx",        // 16- httpx
}

// passive 被动模式
// https://github.com/projectdiscovery/tlsx
var (
	caseScanFunc  sync.Map
	CaseScanFunc1 = map[int64]EngineFuncType{
		ScanType_SSLInfo:    nil, // 01- SSL信息分析，并对域名信息进行收集、进入下一步流程
		ScanType_SubDomain:  nil, // 02- 子域名爆破，新域名回归 到:  1 <-- -> 2，做去重处理
		ScanType_MergeIps:   nil, // 03- 默认自动合并ip，记录ip与域名的关联关系，再发送payload时考虑：相同ip不同域名，相同payload分别发送 合并相同目标 若干域名的ip，避免扫描时重复
		ScanType_Pswd4hydra: nil, // 04- 密码破解，隐含包含了: 端口扫描(05-masscan + 06-nmap)
		//ScanType_Masscan:    portScan.MassScanTarget, // 05- 合并后的ip 进行快速端口扫描
		//ScanType_Nmap:       portScan.DoNmap,         // 06、精准 端口指纹，排除masscan已经识别的几种指纹
		ScanType_IpInfo: nil, // 07- 获取ip info
		//ScanType_GoPoc:           pocs_go.POCcheck4Engin,  // 08- go-poc 检测, 隐含包含了: ScanType_WebDirScan,端口扫描(05-masscan + 06-nmap)
		ScanType_PortsWeb:        nil, // 09- web端口识别，Naabu,识别 https，识别存活的web端口，再进入下一流程
		ScanType_WebFingerprints: nil, // 10- web指纹，识别蜜罐，并标识
		ScanType_WebDetectWaf:    nil, // 11- detect WAF
		ScanType_WebScrapy:       nil, // 12- 爬虫分析，form表单识别，字段名识别，form action提取；
		ScanType_WebInfo:         nil, // 13- server、x-powerby、x***，url、ip、其他敏感信息（姓名、电话、地址、身份证）
		//ScanType_WebVulsScan:     nuclei_Yaml.RunNucleiEngin, // 14-nuclei
		//ScanType_WebDirScan:      brute.FileFuzz4Engin,       // 14-dir爆破,Gobuster,file fuzz
		ScanType_Httpx: nil, // 16- httpx
	}
)
