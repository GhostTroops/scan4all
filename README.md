vscan
================================
轻量、快速、跨平台 的红队外网打点扫描器框架

### 1.options
```
-host                           Host or Url to find ports for		
-top-ports                      Top Ports to scan (full|http|top100|top-1000)		
-iL                             File containing list of hosts to enumerate ports		
-p                              Ports to scan (80, 80,443, 100-200, (-p - for full port scan)		
-ping                           Use ping probes for verification of host		
-ports-file                     File containing ports to enumerate for on hosts		
-o                              File to write output to (optional)		
-json                           Write output in JSON lines Format		
-silent                         Show found ports only in output		
-retries                        DefaultRetriesSynScan, "Number of retries for the port scan probe		
-rate                           DefaultRateSynScan, "Rate of port scan probe requests		
-v                              Show Verbose output		
-no-color                       Don't Use colors in output		
-timeout                        DefaultPortTimeoutSynScan, "Millisecond to wait before timing out		
-exclude-ports                  Ports to exclude from enumeration		
-verify                         Validate the ports again with TCP verification		
-version                        Show version of naabu		
-exclude-hosts                  Specifies a comma-separated list of targets to be excluded from the scan (ip, cidr)		
-exclude-file                   Specifies a newline-delimited file with targets to be excluded from the scan (ip, cidr)		
-debug                          Enable debugging information		
-source-ip                      Source Ip		
-interface                      Network Interface to use for port scan		
-exclude-cdn                    Skip full port scans for CDNs (only checks for 80,443)		
-warm-up-time                   Time in seconds between scan phases		
-interface-list                 List available interfaces and public ip		
-config                         Config file		
-nmap                           Invoke nmap scan on targets (nmap must be installed)		
-nmap-cli                       Nmap command line (invoked as COMMAND + TARGETS)		
-c                              General internal worker threads		
-stats                          Display stats of the running scan		
-scan-all-ips                   Scan all the ips		
-s                              Scan Type (s - SYN, c - CONNECT)	
-proxy                          Httpx Proxy, eg (http://127.0.0.1:8080|socks5://127.0.0.1:1080)       	
```

### 2.Build

Requirements:
  * [Go 1.15 版本以上](https://golang.org/dl/)
  * [libpcap](https://www.tcpdump.org/)
```
git clone https://github.com/veo/vscan.git
cd vscan
go build
```


### 3.功能
#### 3.1 端口扫描，站点访问

1.支持CONNECT、SYN扫描，C段扫描等功能

2.可以直接输入网址进行扫描（不带http://），即使网址使用了CDN，也可以正常扫描

3.支持CDN检测，检测到CDN则只返回80,443端口

4.智能识别https，自动信任证书

其他功能自行探索，详情见options

#### 3.2 指纹识别
3.2.1 基础指纹识别

可以快速识别网站的标题、网址、状态码、指纹等

使用了wappalyzergo库作为指纹识别，[wappalyzergo](https://github.com/projectdiscovery/wappalyzergo)库已集成在源码内，二次开发可以在./pkg/httpx/fingerprint/fingerprints_data.go 自行修改

3.2.2 智能探索型指纹识别

基于敏感文件扫描，扫描到某些文件，再进行指纹鉴定，二次开发可自行修改

#### 3.3 漏洞扫描（nday、0day检测）
为了方便，exp版块都是直接使用go文件，每个文件都是单独完整的poc

添加poc需要写一个go的程序，放到exp文件夹下，指定一个入口函数，设置代理为 httpProxy = exp.HttpProxy,指定输入输出，并在./pkg/httpx/runner/runner.go 添加检测项

例如

shiro exp 入口函数：
```
func Check(url string) (key string) {
	getCommandArgs()
	shiro_url = url
	httpProxy = exp.HttpProxy
	key = keyCheck(url)
	return key

```

shiro exp 添加检测项：
```
matches := r.wappalyzer.Fingerprint(resp.Headers, resp.Data)
for match := range matches {
    technologies = append(technologies, match)
    if match == "Shiro" {
        key := shiro.Check(URL.String())
        if key != ""{
            technologies = append(technologies, "key:"+key)
        }
    }
}
```

#### 3.4 智能后台弱口令扫描，中间件弱口令扫描

内置了两个账号 admin/test，密码为top100，如果成功识别后台会标记为\[登录页\]，成功构建登录包会自动爆破出密码

如：

`http://xxx.xxx.xxx.xxx:8080 [302,200] [登录 - 后台] [exp-shiro|key:Z3VucwAAAAAAAAAAAAAAAA==,Java,登录页,brute-admin|admin:123456] [http://xxx.xxx.xxx.xxx:8080/login;JSESSIONID=8417fe14-f529-46a7-a67e-bbe96429cbd0]`

包含爆破板块
1. 没有使用验证码，没有使用vue等前端框架的后台智能爆破
2. basic爆破
3. tomcat登录爆破
4. weblogic登录爆破

#### 3.5 敏感文件扫描

扫描 备份文件、swagger-ui、spring actuator、上传接口、测试文件等敏感链接

### 4.演示

#### 4.1 扫描Tomcat 
```
➜  vscan git:(main) ✗ ./vscan -host 127.0.0.1 -p 8080
[INF] Running CONNECT scan with non root privileges
[INF] Found 1 ports on host 127.0.0.1 (127.0.0.1)
127.0.0.1:8080
tomcat-exp-sucess|CVE_2017_12615|--"http://127.0.0.1:8080/vtest.txt"
tomcat-brute-sucess|Tomcat-manager:manager--http://127.0.0.1:8080
tomcat-exp-sucess|127.0.0.1:8009 Tomcat AJP LFI is vulnerable, Tomcat version: 8.5.40
http://127.0.0.1:8080 [200] [Apache Tomcat/8.5.40] [Apache Tomcat,Java,Tomcat登录页,brute-tomcat|Tomcat-manager:manager,exp-tomcat|CVE_2017_12615,exp-tomcat|CVE-2020-1938]] [file_fuzz："http://127.0.0.1:8080/manager/html"]
```

#### 4.2 扫描weblogic
```
➜  vscan git:(main) ✗ ./vscan -host 127.0.0.1 -p 7001
[INF] Running CONNECT scan with non root privileges
[INF] Found 1 ports on host 127.0.0.1 (127.0.0.1)
127.0.0.1:7001
weblogic-brute-sucess|weblogic:welcome1--http://127.0.0.1:7001/console/
http://127.0.0.1:7001 [404] [Error 404--Not Found] [brute-weblogic|weblogic:welcome1,weblogic] [file_fuzz："http://127.0.0.1:7001/console/login/LoginForm.jsp"]

```

#### 4.3 扫描后台智能爆破
```
➜  vscan git:(main) ✗ ./vscan -host 127.0.0.1 -p 8080
[INF] Running CONNECT scan with non root privileges
[INF] Found 1 ports on host 127.0.0.1 (127.0.0.1)
127.0.0.1:8080
http://127.0.0.1:8080 [302,200] [登录 - 后台] [Java,登录页,brute-admin|admin:123456] [http://xxx.xxx.xxx.xxx:8080/login]
```

#### 4.4 扫描敏感文件
```
➜  vscan git:(main) ✗ ./vscan -host 127.0.0.1 -p 443,8081
[INF] Running CONNECT scan with non root privileges
[INF] Found 1 ports on host 127.0.0.1 (127.0.0.1)
127.0.0.1:443
127.0.0.1:8081
https://127.0.0.1 [403] [403 Forbidden] [Apache,OpenSSL,Windows Server] [file_fuzz："https://127.0.0.1:443/.git/config","https://127.0.0.1:443/.svn/entries"]
http://127.0.0.1:8001 [302,302,200] [Data Search] [Java,Google Font API,Bootstrap,jQuery,登录页,Font Awesome,Shiro] [ http://127.0.0.1:8001/main/login.html ] [file_fuzz："http://127.0.0.1:8001/druid/index.html","http://127.0.0.1:8081/actuator","http://127.0.0.1:8081/actuator/env"]
```

### 5.TO DO

1.解析http以外的端口指纹

### 6.目前正在做的

1.加入weblogic，jboss等反序列化检测

2.加入其他cms nday



