[![Tweet](https://img.shields.io/twitter/url/http/Hktalent3135773.svg?style=social)](https://twitter.com/intent/follow?screen_name=Hktalent3135773) [![Follow on Twitter](https://img.shields.io/twitter/follow/Hktalent3135773.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=Hktalent3135773) [![GitHub Followers](https://img.shields.io/github/followers/hktalent.svg?style=social&label=Follow)](https://github.com/hktalent/)
<p align="center">
   <a href="/README_CN.md">README_中文</a> •
   <a href="/static/Installation.md">Compile/Install/Run</a> •
   <a href="/static/usage.md">Parameter Description</a> •
   <a href="/static/running.md">How to use</a> •
   <a href="/static/scenario.md">Scenario</a> •
   <a href="/static/pocs.md">POC List</a> •
   <a href="/static/development.md">Custom Scan</a> •
   <a href="/static/NicePwn.md">Best Practices</a>
</p>

# Features

<h1 align="center">
<img width="928" alt="image" src="https://user-images.githubusercontent.com/18223385/175768227-098c779b-6c5f-48ee-91b1-c56e3daa9c87.png">
</h1>

- What is scan4all: integrated vscan, nuclei, ksubdomain, subfinder, etc., fully automated and intelligent
  Code-level optimization, parameter optimization, and individual modules, such as vscan filefuzz, have been rewritten for these integrated projects.
  In principle, do not repeat the wheel, unless there are bugs, problems
- Cross-platform: based on golang implementation, lightweight, highly customizable, open source, supports Linux, windows, mac os, etc.
- Support [20] password blasting, support custom dictionary, open by "priorityNmap": true
  * RDP
  * SSH
  * rsh-spx
  * Mysql
  * MsSql
  * Oracle
  * Postgresql
  * Redis
  * FTP
  * Mongodb
  * SMB, also detect MS17-010 (CVE-2017-0143, CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, CVE-2017-0147, CVE-2017-0148), SmbGhost (CVE- 2020-0796)
  * Telnet
  * Snmp
  * Wap-wsp (Elasticsearch)
  * RouterOs
  * HTTP BasicAuth
  * Weblogic, enable nuclei through enableNuclei=true at the same time, support T3, IIOP and other detection
  * Tomcat
  * Jboss
  * Winrm(wsman)
- By default, http password intelligent blasting is enabled, and it will be automatically activated when an HTTP password is required, without manual intervention
- Detect whether there is nmap in the system, and enable nmap for fast scanning through priorityNmap=true, which is enabled by default, and the optimized nmap parameters are faster than masscan
  Disadvantages of using nmap: Is the network bad, because the traffic network packet is too large, which may lead to incomplete results
  Using nmap additionally requires setting the root password to an environment variable

```bash  
  export PPSSWWDD=yourRootPswd 
```

  More references: config/doNmapScan.sh
  By default, naabu is used to complete port scanning -stats=true to view the scanning progress
  Can I not scan ports?
```bash
noScan=true ./scan4all -l list.txt -v
````
- Fast 15000+ POC detection capabilities, PoCs include: 
  * nuclei POC
  ## Nuclei Templates Top 10 statistics

|    TAG    | COUNT |    AUTHOR     | COUNT |    DIRECTORY     | COUNT | SEVERITY | COUNT |  TYPE   | COUNT |
|-----------|-------|---------------|-------|------------------|-------|----------|-------|---------|-------|
| cve       |  1294 | daffainfo     |   605 | cves             |  1277 | info     |  1352 | http    |  3554 |
| panel     |   591 | dhiyaneshdk   |   503 | exposed-panels   |   600 | high     |   938 | file    |    76 |
| lfi       |   486 | pikpikcu      |   321 | vulnerabilities  |   493 | medium   |   766 | network |    50 |
| xss       |   439 | pdteam        |   269 | technologies     |   266 | critical |   436 | dns     |    17 |
| wordpress |   401 | geeknik       |   187 | exposures        |   254 | low      |   211 |         |       |
| exposure  |   355 | dwisiswant0   |   169 | misconfiguration |   207 | unknown  |     7 |         |       |
| cve2021   |   322 | 0x_akoko      |   154 | token-spray      |   206 |          |       |         |       |
| rce       |   313 | princechaddha |   147 | workflows        |   187 |          |       |         |       |
| wp-plugin |   297 | pussycat0x    |   128 | default-logins   |   101 |          |       |         |       |
| tech      |   282 | gy741         |   126 | file             |    76 |          |       |         |       |

**281 directories, 3922 files**.
* vscan POC
  * vscan POC includes: xray 2.0 300+ POC, go POC, etc.
* scan4all POC

- Support 7000+ web fingerprint scanning, identification:
  * httpx fingerprint
    * vscan fingerprint
    * vscan fingerprint: including eHoleFinger, localFinger, etc.
  * scan4all fingerprint

- Support 146 protocols and 90000+ rule port scanning
  * Depends on protocols and fingerprints supported by nmap
- Fast HTTP sensitive file detection, can customize dictionary
- Landing page detection
- Supports multiple types of input - STDIN/HOST/IP/CIDR/URL/TXT
- Supports multiple output types - JSON/TXT/CSV/STDOUT
- Highly integratable: Configurable unified storage of results to Elasticsearch [strongly recommended]
- Smart SSL Analysis:
  * In-depth analysis, automatically correlate the scanning of domain names in SSL information, such as *.xxx.com, and complete subdomain traversal according to the configuration, and the result will automatically add the target to the scanning list
  * Support to enable *.xx.com subdomain traversal function in smart SSL information, export EnableSubfinder=true, or adjust in the configuration file
- Automatically identify the case of multiple IPs associated with a domain (DNS), and automatically scan the associated multiple IPs
- Smart processing:
  * 1. When the IPs of multiple domain names in the list are the same, merge port scans to improve efficiency
  * 2. Intelligently handle http abnormal pages, and fingerprint calculation and learning
- Automated supply chain identification, analysis and scanning
- Link python3 <a href=https://github.com/hktalent/log4j-scan>log4j-scan</a>
  * This version blocks the bug that your target information is passed to the DNS Log Server to avoid exposing vulnerabilities
  * Added the ability to send results to Elasticsearch for batch, touch typing
  * There will be time in the future to implement the golang version
    how to use?
```bash
mkdir ~/MyWork/;cd ~/MyWork/;git clone https://github.com/hktalent/log4j-scan
````
- Intelligently identify honeypots and skip targets. This function is disabled by default. You can set EnableHoneyportDetection=true to enable
- Highly customizable: allow to define your own dictionary through config/config.json configuration, or control more details, including but not limited to: nuclei, httpx, naabu, etc.

# work process

<img src="static/workflow.jpg">

# how to install
download from
<a href=https://github.com/hktalent/scan4all/releases>Releases</a>
```bash
go install github.com/hktalent/scan4all@2.6.1
scan4all -h
````
# how to use
- 1. Start Elasticsearch, of course you can use the traditional way to output, results
```bash
mkdir -p logs data
docker run --restart=always --ulimit nofile=65536:65536 -p 9200:9200 -p 9300:9300 -d --name es -v $PWD/logs:/usr/share/elasticsearch/logs -v $PWD/config/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml -v $PWD/config/jvm.options:/usr/share/elasticsearch/config/jvm.options -v $PWD/data:/usr/share/elasticsearch/data hktalent/elasticsearch:7.16.2
# Initialize the es index, the result structure of each tool is different, and it is stored separately
./config/initEs.sh

# Search syntax, more query methods, learn Elasticsearch by yourself
http://127.0.0.1:9200/nmap_index/_doc/_search?q=_id:192.168.0.111
where 92.168.0.111 is the target to query

````
- Please install nmap by yourself before use
  <a href=https://github.com/hktalent/scan4all/discussions>Using Help</a>
```bash
go build
# Precise scan url list UrlPrecise=true
UrlPrecise=true ./scan4all -l xx.txt
# Disable adaptation to nmap and use naabu port to scan its internally defined http-related ports
priorityNmap=false ./scan4all -tp http -list allOut.txt -v
````

# Work Plan
- Integrate web-cache-vulnerability-scanner to realize HTTP smuggling smuggling and cache poisoning detection
- Linkage with metasploit-framework, on the premise that the system has been installed, cooperate with tmux, and complete the linkage with the macos environment as the best practice
- Integrate more fuzzers <!-- gryffin -->, such as linking sqlmap
- Integrate chromedp to achieve screenshots of landing pages, detection of front-end landing pages with pure js and js architecture, and corresponding crawlers (sensitive information detection, page crawling)
- Integrate nmap-go to improve execution efficiency, dynamically parse the result stream, and integrate it into the current task waterfall
- Integrate ksubdomain to achieve faster subdomain blasting
- Integrate spider to find more bugs
- Semi-automatic fingerprint learning to improve accuracy; specify fingerprint name, configure

# Changelog
- 2022-07-20 fix and PR nuclei <a href=https://github.com/projectdiscovery/nuclei/issues/2301>#2301</a> 并发多实例的bug
- 2022-07-20 add web cache vulnerability scanner
- 2022-07-19 PR nuclei <a href=https://github.com/projectdiscovery/nuclei/pull/2308>#2308</a> add dsl function: substr aes_cbc
- 2022-07-19 添加dcom Protocol enumeration network interfaces
- 2022-06-30 嵌入式集成私人版本nuclei-templates 共3744个YAML POC； 1、集成Elasticsearch存储中间结果 2、嵌入整个config目录到程序中
- 2022-06-27 优化模糊匹配，提高正确率、鲁棒性;集成ksubdomain进度
- 2022-06-24 优化指纹算法；增加工作流程图
- 2022-06-23 添加参数ParseSSl，控制默认不深度分析SSL中的DNS信息，默认不对SSL中dns进行扫描；优化：nmap未自动加.exe的bug；优化windows下缓存文件未优化体积的bug
- 2022-06-22 集成11种协议弱口令检测、密码爆破：ftp、mongodb、mssql、mysql、oracle、postgresql、rdp、redis、smb、ssh、telnet，同时优化支持外挂密码字典
- 2022-06-20 集成Subfinder，域名爆破，启动参数导出EnableSubfinder=true，注意启动后很慢； ssl证书中域名信息的自动深度钻取
  允许通过 config/config.json 配置定义自己的字典，或设置相关开关
- 2022-06-17 优化一个域名多个IP的情况，所有IP都会被端口扫描，然后按照后续的扫描流程
- 2022-06-15 此版本增加了过去实战中获得的几个weblogic密码字典和webshell字典
- 2022-06-10 完成核的整合，当然包括核模板的整合
- 2022-06-07 添加相似度算法来检测 404
- 2022-06-07 增加http url列表精准扫描参数，根据环境变量UrlPrecise=true开启

# Donation
| Wechat Pay | AliPay | Paypal | BTC Pay |BCH Pay |
| --- | --- | --- | --- | --- |
|<img src=https://github.com/hktalent/myhktools/blob/master/md/wc.png>|<img width=166 src=https://github.com/hktalent/myhktools/blob/master/md/zfb.png>|[paypal](https://www.paypal.me/pwned2019) **miracletalent@gmail.com**|<img width=166 src=https://github.com/hktalent/myhktools/blob/master/md/BTC.png>|<img width=166 src=https://github.com/hktalent/myhktools/blob/master/md/BCH.jpg>|
