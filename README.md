vscan
================================
开源、轻量、快速、跨平台 的红队外网打点扫描器

# 1.options
```

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
   -skip-waf              Not filefuzz scan to prevent interception by WAF
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

# 3.Note
#### 3.1 基本使用命令
hosts.txt -> 导入的hosts列表，格式：IP或域名或C段，一行一个

`vscan -l hosts.txt -top-ports http -o out.txt `

#### 3.2 万数以上的扫描
支持万数量级以上的扫描，一万个扫描任务挂在后台，一般一天就扫描完
#### 3.3 筛选结果
`cat out.txt|grep "POC"`

# 4.功能
### 4.1 端口扫描，站点访问

1.支持CONNECT、SYN扫描，C段扫描等功能

2.可以直接输入网址进行扫描（不带http://），即使网址使用了CDN，也可以正常扫描

3.支持CDN检测，使用-exclude-cdn选项检测到CDN会只返回80,443端口

4.智能识别https，自动信任证书

其他功能自行探索，详情见options

### 4.2 指纹识别
4.2.1 基础指纹识别

可以快速识别网站的标题、网址、状态码、指纹等

使用了wappalyzergo库作为指纹识别，[wappalyzergo](https://github.com/projectdiscovery/wappalyzergo)库已集成在源码内，二次开发可以在./pkg/httpx/fingerprint/fingerprints_data.go 自行修改

4.2.2 智能探索型指纹识别

基于敏感文件扫描，扫描到某些文件，再进行指纹鉴定，二次开发可自行修改

### 4.3 漏洞检测（nday、0day检测）

目前包含的CVE检测项

1.Tomcat

CVE_2017_12615、CVE_2020_1938

2.Weblogic

CVE_2014_4210、CVE_2017_10271、CVE_2017_3506、CVE_2018_2894、CVE_2019_2725、CVE_2020_14882、CVE_2020_14883、CVE_2020_2883、CVE_2021_2109

3.Shiro

Shiro550

4.Fastjson

5.Jboss

CVE_2017_12149


#### 自行添加poc方式:

为了方便，poc版块都是直接使用go文件，每个文件都是单独完整的poc

poc的编写过程可以使用./pkg/util.go内的函数pkg.HttpRequset

添加poc需要写一个go的文件，放到poc文件夹下，指定一个入口函数，指定输入输出，并在./poc/checklist.go 添加检测项

例如

CVE_2017_12615 poc：
```
func CVE_2017_12615(url string) bool {
	if req, err := pkg.HttpRequset(url+"/vtset.txt", "PUT", "test", false, nil); err == nil {
		if req.StatusCode == 204 || req.StatusCode == 201 {
			fmt.Printf("tomcat-exp-sucess|CVE_2017_12615|--\"%s/vtest.txt\"\n", url)
			return true
		}
	}
	return false
}
```

CVE_2017_12615 poc 添加检测项：
```
case "Apache Tomcat":
    if tomcat.CVE_2017_12615(URL.String()) {
	    technologies = append(technologies, "exp-tomcat|CVE_2017_12615")
	}
```

## 4.4 智能后台弱口令扫描，中间件弱口令扫描

后台弱口令检测内置了两个账号 admin/test，密码为top100，如果成功识别首页有登录会标记为\[LoginPage\]，如果识别可能是后台登录页会标记为\[AdminLoginPage\]，都会尝试构建登录包会自动检测弱口令

如：

`http://127.0.0.1:8080 [302,200] [登录 - 后台] [exp-shiro|key:Z3VucwAAAAAAAAAAAAAAAA==,Java,LoginPage,brute-admin|admin:123456] [http://127.0.0.1:8080/login]`

包含弱口令检测板块
1. 没有使用验证码，没有使用vue等前端框架的后台智能弱口令检测
2. basic弱口令检测
3. tomcat弱口令检测
4. weblogic弱口令检测
5. jboss弱口令检测

## 4.5 敏感文件扫描

扫描 备份、swagger-ui、spring actuator、上传接口、测试文件等敏感文件，字典在 ./brute/dicts.go 内置，可自行修改

# 5.演示

## 5.1 扫描Shiro
```
➜  vscan git:(main) ✗ ./vscan -host 127.0.0.1 -p 8080
[INF] Running CONNECT scan with non root privileges
[INF] Found 1 ports on host 127.0.0.1 (127.0.0.1)
127.0.0.1:8080
[+] Found vuln Shiro CVE_2016_4437| URL: http://127.0.0.1:8080 CBC-KEY: kPH+bIxk5D2deZiIxcaaaA==
http://127.0.0.1:8080 [302,200] [后台管理系统] [Java,Shiro,exp-shiro|key:kPH+bIxk5D2deZiIxcaaaA==,LoginPage] [ http://103.71.153.11:8080/login.jsp ]
```

## 5.2 扫描Tomcat 
```
➜  vscan git:(main) ✗ ./vscan -host 127.0.0.1 -p 8080
[INF] Running CONNECT scan with non root privileges
[INF] Found 1 ports on host 127.0.0.1 (127.0.0.1)
127.0.0.1:8080
[+] Found vuln Tomcat password|Tomcat-manager:manager--http://127.0.0.1:8080
[+] Found vuln Tomcat CVE_2017_12615|--"http://127.0.0.1:8080/vtest.txt"
[+] Found vuln Tomcat CVE_2020_1938 127.0.0.1:8009 Tomcat AJP LFI is vulnerable, Tomcat version: 8.5.40
http://127.0.0.1:8080 [200] [Apache Tomcat/8.5.40] [Apache Tomcat,Java,Tomcat登录页,brute-tomcat|Tomcat-manager:manager,exp-tomcat|CVE_2017_12615,exp-tomcat|CVE-2020-1938]] [file_fuzz："http://127.0.0.1:8080/manager/html"]
```

## 5.3 扫描weblogic
```
➜  vscan git:(main) ✗ go run main.go -host 127.0.0.1 -p 7001
[INF] Running CONNECT scan with non root privileges
[INF] Found 1 ports on host 127.0.0.1 (127.0.0.1)
127.0.0.1:7001
[+] Found vuln WebLogic password|weblogic:welcome1|http://127.0.0.1:7001/console/
[+] Found vuln WebLogic CVE_2017_3506|http://127.0.0.1:7001
[+] Found vuln WebLogic CVE_2017_10271|http://127.0.0.1:7001
[+] Found vuln WebLogic CVE_2019_2725|http://127.0.0.1:7001
[+] Found vuln WebLogic CVE_2020_2883|http://127.0.0.1:7001
[+] Found vuln WebLogic CVE_2021_2109|http://127.0.0.1:7001
http://127.0.0.1:7001 [404] [Error 404--Not Found] [brute-weblogic|weblogic:welcome1,exp-weblogic|CVE_2017_10271,exp-weblogic|CVE_2017_3506,exp-weblogic|CVE_2019_2725,exp-weblogic|CVE_2020_2883,exp-weblogic|CVE_2021_2109,weblogic] [file_fuzz："http://127.0.0.1:7001/console/login/LoginForm.jsp"]

```

## 5.4 扫描jboss
```
➜  vscan git:(main) ✗ go run main.go -host 127.0.0.1 -p 8888
[INF] Running CONNECT scan with non root privileges
[INF] Found 1 ports on host 127.0.0.1 (127.0.0.1)
127.0.0.1:8888
[+] Found vuln Jboss password|jboss:jboss|http://127.0.0.1:8888/jmx-console/
[+] Found vuln Jboss CVE_2017_12149|http://127.0.0.1:8888
http://127.0.0.1:8888 [200] [Welcome to JBoss AS] [Apache Tomcat,JBoss Application Server,JBoss Web,Java,Java Servlet,brute-jboss|jboss:jboss,exp-jboss|CVE_2017_12149,jboss,jboss_as]
```

## 5.5 扫描后台智能爆破
```
➜  vscan git:(main) ✗ ./vscan -host 127.0.0.1 -p 8080
[INF] Running CONNECT scan with non root privileges
[INF] Found 1 ports on host 127.0.0.1 (127.0.0.1)
127.0.0.1:8080
[+] Found vuln admin password|admin:123456|http://127.0.0.1:8080
http://127.0.0.1:8080 [302,200] [登录 - 后台] [Java,LoginPage,brute-admin|admin:123456] [http://127.0.0.1:8080/login]
```

## 5.6 扫描敏感文件
```
➜  vscan git:(main) ✗ ./vscan -host 127.0.0.1 -p 443,8081
[INF] Running CONNECT scan with non root privileges
[INF] Found 2 ports on host 127.0.0.1 (127.0.0.1)
127.0.0.1:443
127.0.0.1:8081
https://127.0.0.1 [403] [403 Forbidden] [Apache,OpenSSL,Windows Server] [file_fuzz："https://127.0.0.1:443/.git/config","https://127.0.0.1:443/.svn/entries"]
http://127.0.0.1:8001 [302,302,200] [Data Search] [Java,Google Font API,Bootstrap,jQuery,LoginPage,Font Awesome,Shiro] [ http://127.0.0.1:8001/main/login.html ] [file_fuzz："http://127.0.0.1:8001/druid/index.html","http://127.0.0.1:8081/actuator","http://127.0.0.1:8081/actuator/env"]
```

# 6.TO DO

1.端口扫描和WEB扫描并发，30s内开始出结果

2.解析http以外的端口指纹

# 7.目前正在做的

1.加入struts2指纹识别，poc

2.加入其他cms nday



