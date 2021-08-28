vscan
================================
开源、轻量、快速、跨平台 的红队外网打点扫描器

# 1.options
```
-host                           Host or Url or Cidr to find ports for		
-top-ports                      Top Ports to scan (full|http|top100|top-1000)		
-iL                             File containing list of hosts to enumerate ports		
-p                              Ports to scan (80, 80,443, 100-200, (-p - for full port scan)		
-ping                           Use ping probes for verification of host		
-ports-file                     File containing ports to enumerate for on hosts		
-o                              File to write output to (optional)		
-json                           Write output host and port in JSON lines Format		
-silent                         Show found ports only in output		
-retries                        Number of retries for the port scan probe		
-rate                           Rate of port scan probe requests		
-v                              Show Verbose output		
-no-color                       Don't Use colors in output		
-skip-waf                       Only asset detection, not vulnerability scan to prevent interception by WAF
-timeout                        Millisecond to wait before timing out		
-exclude-ports                  Ports to exclude from enumeration		
-verify                         Validate the ports again with TCP verification		
-version                        Show version of vscan		
-exclude-hosts                  Specifies a comma-separated list of targets to be excluded from the scan (ip, cidr)		
-exclude-file                   Specifies a newline-delimited file with targets to be excluded from the scan (ip, cidr)		
-debug                          Enable debugging information		
-source-ip                      Source Ip		
-interface                      Network Interface to use for port scan		
-exclude-cdn                    Skip full port scans for CDNs (only checks for 80,443)		
-warm-up-time                   Time in seconds between scan phases		
-interface-list                 List available interfaces and public ip
-nmap                           Invoke nmap scan on targets (nmap must be installed)		
-nmap-cli                       Nmap command line (invoked as COMMAND + TARGETS)		
-c                              General internal worker threads		
-stats                          Display stats of the running scan		
-scan-all-ips                   Scan all the ips		
-s                              Scan Type (s - SYN, c - CONNECT)	
-proxy                          Httpx Proxy, eg (http://127.0.0.1:8080|socks5://127.0.0.1:1080)       	
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

3.支持CDN检测，检测到CDN则只返回80,443端口

4.智能识别https，自动信任证书

其他功能自行探索，详情见options

### 3.2 指纹识别
3.2.1 基础指纹识别

可以快速识别网站的标题、网址、状态码、指纹等

使用了wappalyzergo库作为指纹识别，[wappalyzergo](https://github.com/projectdiscovery/wappalyzergo)库已集成在源码内，二次开发可以在./pkg/httpx/fingerprint/fingerprints_data.go 自行修改

3.2.2 智能探索型指纹识别

基于敏感文件扫描，扫描到某些文件，再进行指纹鉴定，二次开发可自行修改

### 3.3 漏洞检测（nday、0day检测）

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

添加poc需要写一个go的文件，放到poc文件夹下，指定一个入口函数，指定输入输出，并在./pkg/httpx/runner/runner.go 添加检测项

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

## 3.4 智能后台弱口令扫描，中间件弱口令扫描

后台弱口令检测内置了两个账号 admin/test，密码为top100，如果成功识别后台会标记为\[登录页\]，成功构建登录包会自动检测

如：

`http://127.0.0.1:8080 [302,200] [登录 - 后台] [exp-shiro|key:Z3VucwAAAAAAAAAAAAAAAA==,Java,登录页,brute-admin|admin:123456] [http://127.0.0.1:8080/login]`

包含弱口令检测板块
1. 没有使用验证码，没有使用vue等前端框架的后台智能弱口令检测
2. basic弱口令检测
3. tomcat弱口令检测
4. weblogic弱口令检测
5. jboss弱口令检测

## 3.5 敏感文件扫描

扫描 备份、swagger-ui、spring actuator、上传接口、测试文件等敏感文件，字典在 ./brute/util.go 内置，可自行修改

# 4.演示

## 4.1 扫描Shiro
```
➜  vscan git:(main) ✗ ./vscan -host 127.0.0.1 -p 8080
[INF] Running CONNECT scan with non root privileges
[INF] Found 1 ports on host 127.0.0.1 (127.0.0.1)
127.0.0.1:8080
[+] Url:  http://127.0.0.1:8080
[+] CBC-KEY: kPH+bIxk5D2deZiIxcaaaA==
[+] rememberMe= wCNa7hauQ2Kq9h5PPUvUNyNp6fBbikYK4eHFCzlkTUcQuJyXevR+3oQRPtq2yMLckX0Eu0jCuOPjzguuKw1p2p5zG9m0w872541/EK7L0tM/VN/eCIDrP/7mTV5Q2B5y3xx+oqjaxoCJD1HarUDItt7LG2erCz1o/S5T7/vk9PSYnJzmqfX1qclfV7hrtEB4
http://127.0.0.1:8080 [302,200] [后台管理系统] [Java,Shiro,exp-shiro|key:kPH+bIxk5D2deZiIxcaaaA==,登录页] [ http://103.71.153.11:8080/login.jsp ]
```

## 4.2 扫描Tomcat 
```
➜  vscan git:(main) ✗ ./vscan -host 127.0.0.1 -p 8080
[INF] Running CONNECT scan with non root privileges
[INF] Found 1 ports on host 127.0.0.1 (127.0.0.1)
127.0.0.1:8080
tomcat-brute-sucess|Tomcat-manager:manager--http://127.0.0.1:8080
tomcat-exp-sucess|CVE_2017_12615|--"http://127.0.0.1:8080/vtest.txt"
tomcat-exp-sucess|CVE_2020_1938 127.0.0.1:8009 Tomcat AJP LFI is vulnerable, Tomcat version: 8.5.40
http://127.0.0.1:8080 [200] [Apache Tomcat/8.5.40] [Apache Tomcat,Java,Tomcat登录页,brute-tomcat|Tomcat-manager:manager,exp-tomcat|CVE_2017_12615,exp-tomcat|CVE-2020-1938]] [file_fuzz："http://127.0.0.1:8080/manager/html"]
```

## 4.3 扫描weblogic
```
➜  vscan git:(main) ✗ go run main.go -host 127.0.0.1 -p 7001
[INF] Running CONNECT scan with non root privileges
[INF] Found 1 ports on host 127.0.0.1 (127.0.0.1)
127.0.0.1:7001
weblogic-brute-sucess|weblogic:welcome1--http://127.0.0.1:7001/console/
weblogic-exp-sucess|CVE_2017_3506|http://127.0.0.1:7001
weblogic-exp-sucess|CVE_2017_10271|http://127.0.0.1:7001
weblogic-exp-sucess|CVE_2019_2725|http://127.0.0.1:7001
weblogic-exp-sucess|CVE_2020_2883|http://127.0.0.1:7001
weblogic-exp-sucess|CVE_2021_2109|http://127.0.0.1:7001
http://127.0.0.1:7001 [404] [Error 404--Not Found] [brute-weblogic|weblogic:welcome1,exp-weblogic|CVE_2017_10271,exp-weblogic|CVE_2017_3506,exp-weblogic|CVE_2019_2725,exp-weblogic|CVE_2020_2883,exp-weblogic|CVE_2021_2109,weblogic] [file_fuzz："http://127.0.0.1:7001/console/login/LoginForm.jsp"]

```

## 4.4 扫描jboss
```
➜  vscan git:(main) ✗ go run main.go -host 127.0.0.1 -p 8888
[INF] Running CONNECT scan with non root privileges
[INF] Found 1 ports on host 127.0.0.1 (127.0.0.1)
127.0.0.1:8888
jboss-brute-sucess|jboss:jboss--http://127.0.0.1:8888/jmx-console/
jboss-exp-sucess|CVE_2017_12149|http://127.0.0.1:8888
http://127.0.0.1:8888 [200] [Welcome to JBoss AS] [Apache Tomcat,JBoss Application Server,JBoss Web,Java,Java Servlet,brute-jboss|jboss:jboss,exp-jboss|CVE_2017_12149,jboss,jboss_as]
```

## 4.5 扫描后台智能爆破
```
➜  vscan git:(main) ✗ ./vscan -host 127.0.0.1 -p 8080
[INF] Running CONNECT scan with non root privileges
[INF] Found 1 ports on host 127.0.0.1 (127.0.0.1)
127.0.0.1:8080
http://127.0.0.1:8080 [302,200] [登录 - 后台] [Java,登录页,brute-admin|admin:123456] [http://xxx.xxx.xxx.xxx:8080/login]
```

## 4.6 扫描敏感文件
```
➜  vscan git:(main) ✗ ./vscan -host 127.0.0.1 -p 443,8081
[INF] Running CONNECT scan with non root privileges
[INF] Found 2 ports on host 127.0.0.1 (127.0.0.1)
127.0.0.1:443
127.0.0.1:8081
https://127.0.0.1 [403] [403 Forbidden] [Apache,OpenSSL,Windows Server] [file_fuzz："https://127.0.0.1:443/.git/config","https://127.0.0.1:443/.svn/entries"]
http://127.0.0.1:8001 [302,302,200] [Data Search] [Java,Google Font API,Bootstrap,jQuery,登录页,Font Awesome,Shiro] [ http://127.0.0.1:8001/main/login.html ] [file_fuzz："http://127.0.0.1:8001/druid/index.html","http://127.0.0.1:8081/actuator","http://127.0.0.1:8081/actuator/env"]
```

# 5.TO DO

1.解析http以外的端口指纹

# 6.目前正在做的

1.加入struts2指纹识别，poc

2.加入其他cms nday



