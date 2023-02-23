package go_utils

// 这涉及一个扫描任务的状态，会表示为若干中状态
// 一旦定义， 产生数据后，绝不能在中间加类型，只能在最后加类型
const (
	ScanType_SSLInfo         = uint64(1 << iota) // 01- SSL信息分析，并对域名信息进行收集、进入下一步流程
	ScanType_SubDomain                           // 02- 子域名爆破，新域名回归 到:  1 <-- -> 2，做去重处理
	ScanType_MergeIps                            // 03- 默认自动合并ip，记录ip与域名的关联关系，再发送payload时考虑：相同ip不同域名，相同payload分别发送 合并相同目标 若干域名的ip，避免扫描时重复
	ScanType_WeakPassword                        // 04- 密码破解，隐含包含了: 端口扫描(05-masscan + 06-nmap)
	ScanType_Masscan                             // 05- 合并后的ip 进行快速端口扫描, 端口扫描工具：masscan 19.1k, https://github.com/robertdavidgraham/masscan
	ScanType_Nmap                                // 06、精准 端口指纹，排除masscan已经识别的几种指纹, 端口扫描工具：Nmap, https://github.com/vulnersCom/nmap-vulners
	ScanType_IpInfo                              // 07- 获取ip info
	ScanType_GoPoc                               // 08- go-poc 检测, 隐含包含了: 端口扫描(05-masscan + 06-nmap)
	ScanType_PortsWeb                            // 09- web端口识别，Naabu,识别 https，识别存活的web端口，再进入下一流程
	ScanType_WebFingerprints                     // 10- web指纹，识别蜜罐，并标识
	ScanType_WebDetectWaf                        // 11- detect WAF
	ScanType_WebScrapy                           // 12- 爬虫分析，form表单识别，字段名识别，form action提取；
	ScanType_WebInfo                             // 13- server、x-powerby、x***，url、ip、其他敏感信息（姓名、电话、地址、身份证）
	ScanType_WebVulsScan                         // 14- 包含 nuclei
	ScanType_WebDirScan                          // 14- dir爆破,Gobuster
	ScanType_Naabu                               // 15- naabu, 服务、目录发现：naabu 2.1k,https://github.com/projectdiscovery/naabu
	ScanType_Httpx                               // 16- httpx, 服务、目录发现：httpx 3.2k,https://github.com/projectdiscovery/httpx
	ScanType_DNSx                                // 17- DNSX
	ScanType_SaveEs                              // 18- Save Es
	ScanType_Jaeles                              // 19 - jaeles
	ScanType_Uncover                             // Uncover
	ScanType_Ffuf                                // ffuf
	ScanType_Amass                               // amass, 子域名：amass 7.2k
	ScanType_Subfinder                           // subfinder, 子域名：Subfinder 5.6k,https://github.com/projectdiscovery/subfinder
	ScanType_Shuffledns                          // shuffledns
	ScanType_Tlsx                                // tlsx
	ScanType_Katana                              // katana
	ScanType_Nuclei                              // nuclei  漏洞扫描：nuclei 8.4k，https://github.com/projectdiscovery/nuclei
	ScanType_Gobuster                            // Gobuster, 服务、目录发现：gobuster 6k,https://github.com/OJ/gobuster// gobuster dns -d google.com -w ~/wordlists/subdomains.txt
	ScanType_RustScan                            // 端口扫描工具：RustScan 6.3k,https://github.com/RustScan/RustScan
	ScanType_Wappalyzer                          // 指纹:wappalyzer 7.5k, https://github.com/wappalyzer/wappalyzer
	ScanType_Scan4all                            // all scan
)

const (
	ScanType_WebFinger = ScanType_WebFingerprints | ScanType_Wappalyzer
	ScanType_Ips       = ScanType_SSLInfo | ScanType_Tlsx | ScanType_Masscan | ScanType_Nmap | ScanType_IpInfo | ScanType_Uncover | ScanType_GoPoc
	ScanType_Webs      = ScanType_SSLInfo | ScanType_Tlsx | ScanType_GoPoc | ScanType_WebFingerprints | ScanType_WebDetectWaf | ScanType_WebVulsScan | ScanType_Nuclei | ScanType_Gobuster | ScanType_Uncover | ScanType_Httpx | ScanType_WebDirScan
)

const (
// 任务类型
//TaskType_Subdomain   = uint64(1 << iota) // 任务类型：子域名
//TaskType_PortScan                        // 任务类型：端口扫描
//TaskType_UrlScan                         // 任务类型：url扫描
//TaskType_Fingerprint                     // 任务类型：指纹识别
//TaskType_VulsScan                        // 任务类型：漏洞扫描
//
//// 任务状态
//Task_Status_Pending     // 任务状态：待执行
//Task_Status_InExecution // 任务状态：执行中
//Task_Status_Completed   // 任务状态：已完成
//
//// 子域名遍历
//SubDomains_Sublist3r // 子域名：Sublist3r 7.1k
//
//// 指纹
//ScanType_Fingerprint_Wappalyzer // 指纹:wappalyzer 7.5k, https://github.com/wappalyzer/wappalyzer
//ScanType_Fingerprint_WhatWeb    // 指纹: WhatWeb 3.8k,https://github.com/urbanadventurer/WhatWeb
//
//// 服务、目录发现
//ScanType_Discovery_Fscan // 服务、目录发现：fscan 3.6k,https://github.com/shadow1ng/fscan
////  Others
//// https://github.com/NVIDIA/NeMo
//// https://github.com/veo/vscan

)

// 获取类型
func GetTypeName(n uint64) string {
	if s, ok := ScanType2Str[n]; ok {
		return s
	}
	return string(Scan4all)
}

func GetTypeNames(n uint64) []string {
	var a []string
	for k, v := range ScanType2Str {
		if n&k == k {
			a = append(a, v)
		}
	}
	return a
}

// 获取 a 类型，并合并到 nSrc 返回
func GetType4Name(nSrc uint64, a ...string) uint64 {
	for _, x := range a {
		if t, ok := ScanType4Int[x]; ok {
			nSrc = nSrc | t
		}
	}
	return nSrc
}

var ScanType4Int = map[string]uint64{}

// 初始化
func init() {
	RegInitFunc(func() {
		for k, v := range ScanType2Str {
			ScanType4Int[v] = k
		}
	})
}

var ScanType2Str = map[uint64]string{
	ScanType_SSLInfo:         "sslInfo",         // 01- SSL信息分析，并对域名信息进行收集、进入下一步流程
	ScanType_SubDomain:       "subdomain",       // 02- 子域名爆破，新域名回归 到:  1 <-- -> 2，做去重处理
	ScanType_MergeIps:        "mergeIps",        // 03- 默认自动合并ip，记录ip与域名的关联关系，再发送payload时考虑：相同ip不同域名，相同payload分别发送 合并相同目标 若干域名的ip，避免扫描时重复
	ScanType_WeakPassword:    "weakPassword",    // 04- 密码破解，隐含包含了: 端口扫描(05-masscan + 06-nmap)
	ScanType_Masscan:         "masscan",         // 05- 合并后的ip 进行快速端口扫描
	ScanType_Nmap:            "nmap",            // 06、精准 端口指纹，排除masscan已经识别的几种指纹
	ScanType_IpInfo:          "ipInfo",          // 07- 获取ip info
	ScanType_GoPoc:           "goPoc",           // 08- go-poc 检测, 隐含包含了: 端口扫描(05-masscan + 06-nmap)
	ScanType_PortsWeb:        "portsWeb",        // 09- web端口识别，Naabu,识别 https，识别存活的web端口，再进入下一流程
	ScanType_WebFingerprints: "webFingerprints", // 10- web指纹，识别蜜罐，并标识
	ScanType_WebDetectWaf:    "webDetectWaf",    // 11- detect WAF
	ScanType_WebScrapy:       "webScrapy",       // 12- 爬虫分析，form表单识别，字段名识别，form action提取；
	ScanType_WebInfo:         "webInfo",         // 13- server、x-powerby、x***，url、ip、其他敏感信息（姓名、电话、地址、身份证）
	ScanType_WebVulsScan:     "webVulsScan",     // 14- 包含 nuclei
	ScanType_WebDirScan:      "webDirScan",      // 14- dir爆破,Gobuster
	ScanType_Naabu:           "naabu",           // 15- naabu
	ScanType_Httpx:           "httpx",           // 16- httpx
	ScanType_DNSx:            "dnsx",            // 17- DNSX
	ScanType_SaveEs:          "saveEs",          // 18- Save Es
	ScanType_Jaeles:          "jaeles",          // 19 - jaeles
	ScanType_Uncover:         "uncover",         // Uncover
	ScanType_Ffuf:            "ffuf",            // ffuf
	ScanType_Amass:           "amass",           // amass
	ScanType_Subfinder:       "subfinder",       // subfinder
	ScanType_Shuffledns:      "shuffledns",      // shuffledns
	ScanType_Tlsx:            "tlsx",            // tlsx
	ScanType_Katana:          "katana",          // katana
	ScanType_Nuclei:          "nuclei",          // nuclei
	ScanType_Gobuster:        "gobuster",        // Gobuster
	ScanType_RustScan:        "rustscan",        //rustscan
	ScanType_Wappalyzer:      "wappalyzer",      // Wappalyzer,包含在httpx中
	ScanType_Scan4all:        "scan4all",        // all scan
}

// 扫描目标，非存储，chan时用
type Target4Chan struct {
	TaskId     string `json:"task_id"`     // 任务id
	ScanWeb    string `json:"scan_web"`    // base64解码后
	ScanType   uint64 `json:"scan_type"`   // 扫描类型,多种ScanType叠加
	ScanConfig string `json:"scan_config"` // 本次任务的若干细节配置，json格式的string
}

// 事件数据
type EventData struct {
	EventType uint64        // 类型：masscan、nmap
	EventData []interface{} // func，parms
	Task      *Target4Chan  // 当前task任务数据
	//Ips            []string                                         // 当前任务相关的ip
	//SubDomains2Ips *map[string]map[string]map[int]map[string]string // 所有子域名 -> ip ->port -> port info
}
