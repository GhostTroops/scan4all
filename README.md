vscan
================================
开源、轻量、快速、跨平台 的红队外网打点扫描器

<a href="https://github.com/veo/vscan/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
[![GitHub release](https://img.shields.io/github/release/veo/vscan.svg)](https://github.com/veo/vscan/releases/latest)

![vscan](img.png)
# 1.options
```
Examples:
 ./vscan -l hosts.txt -top-ports http -o out.txt 

Usage:
  ./vscan [flags]

INPUT:
   -host string                Host to scan ports for
   -list, -l string            File containing list of hosts to scan ports
   -exclude-hosts, -eh string  Specifies a comma-separated list of targets to be excluded from the scan (ip, cidr)
   -exclude-file, -ef string   Specifies a newline-delimited file with targets to be excluded from the scan (ip, cidr)

PORT:
   -port, -p string            Ports to scan (80, 80,443, 100-200
   -top-ports, -tp string      Top Ports to scan (default top 100)
   -exclude-ports, -ep string  Ports to exclude from scan
   -ports-file, -pf string     File containing ports to scan for
   -exclude-cdn, -ec           Skip full port scans for CDNs (only checks for 80,443)

RATE-LIMIT:
   -c int     General internal worker threads (default 25)
   -rate int  Rate of port scan probe request (default 1000)

OUTPUT:
   -o, -output string  File to write output to (optional)
   -json               Write output in JSON lines Format

CONFIGURATION:
   -proxy                 Httpx Proxy, eg (http://127.0.0.1:8080|socks5://127.0.0.1:1080)   
   -skip-waf              Not FileFuzz scan to prevent interception by WAF
   -ceyeapi               ceye.io api key
   -ceyedomain            ceye.io subdomain
   -no-color              Don't Use colors in output	
   -scan-all-ips          Scan all the ips
   -scan-type, -s string  Port scan type (SYN/CONNECT) (default s)
   -source-ip string      Source Ip
   -interface-list, -il   List available interfaces and public ip
   -interface, -i string  Network Interface to use for port scan
   -nmap                  Invoke nmap scan on targets (nmap must be installed)
   -nmap-cli string       nmap command to run on found results (example: -nmap-cli 'nmap -sV')

OPTIMIZATION:
   -retries int       Number of retries for the port scan probe (default 3)
   -timeout int       Millisecond to wait before timing out (default 1000)
   -warm-up-time int  Time in seconds between scan phases (default 2)
   -ping              Use ping probes for verification of host
   -verify            Validate the ports again with TCP verification

DEBUG:
   -debug          Enable debugging information
   -v              Show Verbose output
   -no-color, -nc  Don't Use colors in output
   -silent         Show found ports only in output
   -version        Show version of naabu
   -stats          Display stats of the running scan

```

# 2.Build

Requirements:
  * [Go 1.15 版本以上](https://golang.org/dl/)
  * [libpcap](https://www.tcpdump.org/)
```
git clone https://github.com/veo/vscan.git
cd vscan
go build
```

# 3.功能
### 3.1 端口扫描，站点访问

1.支持CONNECT、SYN扫描，C段扫描等功能

2.可以直接输入网址进行扫描（不带http://），即使网址使用了CDN，也可以正常扫描

3.支持CDN检测，使用-exclude-cdn参数检测到CDN会只扫描80,443端口

4.智能识别https，自动信任证书

其他功能自行探索，详情见options

### 3.2 指纹识别
3.2.1 基础指纹识别

可以快速识别网站的标题、网址、状态码、指纹等

使用了wappalyzergo库作为指纹识别，[wappalyzergo](https://github.com/projectdiscovery/wappalyzergo)库已集成在源码内，详情见./pkg/httpx/fingerprint/fingerprints_data.go

3.2.2 智能探索型指纹识别

基于敏感文件扫描，扫描到某些文件，再进行指纹鉴定，详情见./brute/fuzzfingerprints.go

### 3.3 漏洞检测
<details>
<summary>已支持的漏洞列表 [点击展开] </summary>  
 
```
pocs_go:

 +-------------------+------------------+-------------------------------------------------------------+
 | 系统               | 编号             | 描述                                                         |
 +-------------------+------------------+-------------------------------------------------------------+
 | Apache Shiro      | CVE-2016-4437    | <= 1.2.4, shiro-550, rememberme deserialization rce         |
 | Apache Tomcat     | CVE-2017-12615   | 7.0.0 - 7.0.81, put method any files upload                 |
 | Apache Tomcat     | CVE-2020-1938    | 6, 7 < 7.0.100, 8 < 8.5.51, 9 < 9.0.31 arbitrary file read  |
 | Fsatjson          | VER-1262         | <= 1.2.62 fastjson autotype remote code execution           |
 | Jboss             | CVE_2017_12149   | Jboss AS 5.x/6.x rce                                        |
 | Jenkins           | CVE-2018-1000110 | user search                                                 |
 | Jenkins           | CVE-2018-1000861 | <= 2.153, LTS <= 2.138.3, remote code execution             |
 | Jenkins           | CVE-2018-1003000 | Groovy <= 2.61 Script Security <= 1.49 remote code execution|
 | Jenkins           | Unauthorized     | Unauthorized Groovy script remote code execution            |
 | Oracle Weblogic   | CVE-2014-4210    | 10.0.2 - 10.3.6, weblogic ssrf vulnerability                |
 | Oracle Weblogic   | CVE-2017-3506    | 10.3.6.0, 12.1.3.0, 12.2.1.0-2, weblogic wls-wsat rce       |
 | Oracle Weblogic   | CVE-2017-10271   | 10.3.6.0, 12.1.3.0, 12.2.1.1-2, weblogic wls-wsat rce       |
 | Oracle Weblogic   | CVE-2018-2894    | 12.1.3.0, 12.2.1.2-3, deserialization any file upload       |
 | Oracle Weblogic   | CVE-2019-2725    | 10.3.6.0, 12.1.3.0, weblogic wls9-async deserialization rce |
 | Oracle Weblogic   | CVE-2019-2729    | 10.3.6.0, 12.1.3.0, weblogic wls9-async deserialization rce |
 | Oracle Weblogic   | CVE-2020-2883    | 10.3.6.0, 12.1.3.0, 12.2.1.3-4, iiop t3 deserialization rce |
 | Oracle Weblogic   | CVE-2020-14882   | 10.3.6.0, 12.1.3.0, 12.2.1.3-4, 14.1.1.0, console rce       |
 | Oracle Weblogic   | CVE-2020-14883   | 10.3.6.0, 12.1.3.0, 12.2.1.3-4, 14.1.1.0, console rce       |
 | Oracle Weblogic   | CVE-2021-2109    | 10.3.6.0, 12.1.3.0, 12.2.1.3-4, 14.1.1.0, unauthorized jndi |
 | PHPUnit           | CVE_2017_9841    | 4.x < 4.8.28, 5.x < 5.6.3, remote code execution            |
 | Seeyon            | *                | some poc                                                    |
 | ThinkPHP          | CVE-2019-9082    | < 3.2.4, thinkphp remote code execution                     |
 | ThinkPHP          | CVE-2018-20062   | <= 5.0.23, 5.1.31, thinkphp remote code execution           |
 +-------------------+------------------+-------------------------------------------------------------+
pocs_yml:

xray all pocs

```
</details>

#### 自行添加POC方式:

go文件添加POC：

1.在./pkg/httpx/fingerprint/fingerprints_data.go内添加指纹

2.写一个go文件POC，放到pocs_go文件夹下，指定一个入口函数，指定输入输出，并在./pocs_go/go_poc_check.go 添加检测项（poc的编写过程可以使用./pkg/util.go内的函数pkg.HttpRequset）

例如：

CVE_2017_12615 POC：
```
func CVE_2017_12615(url string) bool {
	if req, err := pkg.HttpRequset(url+"/vtset.txt", "PUT", "test", false, nil); err == nil {
		if req.StatusCode == 204 || req.StatusCode == 201 {
			pkg.POClog(fmt.Sprintf("Found vuln Tomcat CVE_2017_12615|--\"%s/vtest.txt\"\n", url))
			return true
		}
	}
	return false
}
```

CVE_2017_12615 POC ./pocs_go/go_poc_check.go 添加检测项：
```
case "Apache Tomcat":
   if tomcat.CVE_2017_12615(URL) {
				technologies = append(technologies, "exp-Tomcat|CVE_2017_12615")
			}
```

## 3.4 智能后台弱口令扫描，中间件弱口令扫描

后台弱口令检测内置了两个账号 admin/test，密码为top100，如果成功识别首页有登录会标记为 LoginPage，如果识别可能是后台登录页会标记为 AdminLoginPage ，都会尝试构建登录包会自动检测弱口令

如：

`http://127.0.0.1:8080 [302,200] [登录 - 后台] [exp-shiro|key:Z3VucwAAAAAAAAAAAAAAAA==,Java,LoginPage,brute-admin|admin:123456] [http://127.0.0.1:8080/login]`

包含弱口令检测板块
1. 没有使用验证码，没有使用vue等前端框架的后台智能弱口令检测
2. basic弱口令检测
3. tomcat弱口令检测
4. weblogic弱口令检测
5. jboss弱口令检测

## 3.5 敏感文件扫描

扫描 备份、swagger-ui、spring actuator、上传接口、测试文件等敏感文件，字典在 ./brute/dicts.go 内置，可自行修改

