package Const

// 这涉及一个扫描任务的状态，会表示为若干中状态
// 一旦定义， 产生数据后，绝不能在中间加类型，只能在最后加类型
const (
	ScanType_SSLInfo         = int64(1 << iota) // 01- SSL信息分析，并对域名信息进行收集、进入下一步流程
	ScanType_SubDomain                          // 02- 子域名爆破，新域名回归 到:  1 <-- -> 2，做去重处理
	ScanType_MergeIps                           // 03- 默认自动合并ip，记录ip与域名的关联关系，再发送payload时考虑：相同ip不同域名，相同payload分别发送 合并相同目标 若干域名的ip，避免扫描时重复
	ScanType_Pswd4hydra                         // 04- 密码破解，隐含包含了: 端口扫描(05-masscan + 06-nmap)
	ScanType_Masscan                            // 05- 合并后的ip 进行快速端口扫描
	ScanType_Nmap                               // 06、精准 端口指纹，排除masscan已经识别的几种指纹
	ScanType_IpInfo                             // 07- 获取ip info
	ScanType_GoPoc                              // 08- go-poc 检测, 隐含包含了: 端口扫描(05-masscan + 06-nmap)
	ScanType_PortsWeb                           // 09- web端口识别，Naabu,识别 https，识别存活的web端口，再进入下一流程
	ScanType_WebFingerprints                    // 10- web指纹，识别蜜罐，并标识
	ScanType_WebDetectWaf                       // 11- detect WAF
	ScanType_WebScrapy                          // 12- 爬虫分析，form表单识别，字段名识别，form action提取；
	ScanType_WebInfo                            // 13- server、x-powerby、x***，url、ip、其他敏感信息（姓名、电话、地址、身份证）
	ScanType_WebVulsScan                        // 14- nuclei
	ScanType_WebDirScan                         // 14- dir爆破,Gobuster
	ScanType_Naabu                              // 15- naabu
	ScanType_Httpx                              // 16- httpx
	ScanType_DNSx                               // 17- DNSX
	ScanType_SaveEs                             // 18- Save Es
)

const (
// 任务类型
//TaskType_Subdomain   uint64 = 1 << iota // 任务类型：子域名
//TaskType_PortScan    uint64 = 1 << iota // 任务类型：端口扫描
//TaskType_UrlScan     uint64 = 1 << iota // 任务类型：url扫描
//TaskType_Fingerprint uint64 = 1 << iota // 任务类型：指纹识别
//TaskType_VulsScan    uint64 = 1 << iota // 任务类型：漏洞扫描
//
//// 任务状态
//Task_Status_Pending     uint64 = 1 << iota // 任务状态：待执行
//Task_Status_InExecution uint64 = 1 << iota // 任务状态：执行中
//Task_Status_Completed   uint64 = 1 << iota // 任务状态：已完成
//
//// 子域名遍历
//SubDomains_Amass     uint64 = 1 << iota // 子域名：amass 7.2k
//SubDomains_Subfinder uint64 = 1 << iota // 子域名：Subfinder 5.6k,https://github.com/projectdiscovery/subfinder
//SubDomains_Sublist3r uint64 = 1 << iota // 子域名：Sublist3r 7.1k
//SubDomains_Gobuster  uint64 = 1 << iota // 服务、目录发现：gobuster 6k,https://github.com/OJ/gobuster// gobuster dns -d google.com -w ~/wordlists/subdomains.txt
//
//// 端口扫描
//Ip2Ports_VulsCheckFlag_Masscan  uint64 = 1 << iota // 端口扫描工具：masscan 19.1k, https://github.com/robertdavidgraham/masscan
//Ip2Ports_VulsCheckFlag_RustScan uint64 = 1 << iota // 端口扫描工具：RustScan 6.3k,https://github.com/RustScan/RustScan
//Ip2Ports_VulsCheckFlag_Nmap     uint64 = 1 << iota // 端口扫描工具：Nmap, https://github.com/vulnersCom/nmap-vulners
//
//// 指纹
//ScanType_Fingerprint_Wappalyzer uint64 = 1 << iota // 指纹:wappalyzer 7.5k, https://github.com/wappalyzer/wappalyzer
//ScanType_Fingerprint_WhatWeb    uint64 = 1 << iota // 指纹: WhatWeb 3.8k,https://github.com/urbanadventurer/WhatWeb
//ScanType_Fingerprint_EHole      uint64 = 1 << iota // 指纹:EHole 1.4k,https://github.com/EdgeSecurityTeam/EHole
//
//// 服务、目录发现
//ScanType_Discovery_Gobuster uint64 = 1 << iota // 服务、目录发现：gobuster 6k,https://github.com/OJ/gobuster
//ScanType_Discovery_Fscan    uint64 = 1 << iota // 服务、目录发现：fscan 3.6k,https://github.com/shadow1ng/fscan
//ScanType_Discovery_Httpx    uint64 = 1 << iota // 服务、目录发现：httpx 3.2k,https://github.com/projectdiscovery/httpx
//ScanType_Discovery_Naabu    uint64 = 1 << iota // 服务、目录发现：naabu 2.1k,https://github.com/projectdiscovery/naabu
////  Others
//// https://github.com/NVIDIA/NeMo
//// https://github.com/veo/vscan
//
//// 漏洞扫描
//ScanType_Nuclei uint64 = 1 << iota // 漏洞扫描：nuclei 8.4k，https://github.com/projectdiscovery/nuclei
)
