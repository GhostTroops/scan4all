[![Twitter](https://img.shields.io/twitter/url/http/Hktalent3135773.svg?style=social)](https://twitter.com/intent/follow?screen_name=Hktalent3135773) [![Follow on Twitter](https://img.shields.io/twitter/follow/Hktalent3135773.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=Hktalent3135773) [![GitHub Followers](https://img.shields.io/github/followers/hktalent.svg?style=social&label=Follow)](https://github.com/hktalent/) <a target=_blank href="https://chat.51pwn.com:2083/?cnId=51pwn&atRd=true&stChat=1">💬</a>
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

- <a href=https://github.com/hktalent/51Pwn-Platform/blob/main/README.md>Free one id Multi-target web netcat for reverse shell</a>
- What is scan4all: integrated vscan, nuclei, ksubdomain, subfinder, etc., fully automated and intelligent。red team tools
  Code-level optimization, parameter optimization, and individual modules, such as vscan filefuzz, have been rewritten for these integrated projects.
  In principle, do not repeat the wheel, unless there are bugs, problems
- Cross-platform: based on golang implementation, lightweight, highly customizable, open source, supports Linux, windows, mac os, etc.
- Support [23] password blasting, support custom dictionary, open by "priorityNmap": true
  * RDP
  * VNC
  * SSH
  * Socks5
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
  * HTTP BasicAuth(Authorization), contains Webdav、SVN（Apache Subversion） crack
  * Weblogic, enable nuclei through enableNuclei=true at the same time, support T3, IIOP and other detection
  * Tomcat
  * Jboss
  * Winrm(wsman)
  * POP3/POP3S
- By default, http password intelligent blasting is enabled, and it will be automatically activated when an HTTP password is required, without manual intervention
- Detect whether there is nmap in the system, and enable nmap for fast scanning through priorityNmap=true, which is enabled by default, and the optimized nmap parameters are faster than masscan
  Disadvantages of using nmap: Is the network bad, because the traffic network packet is too large, which may lead to incomplete results
  Using nmap additionally requires setting the root password to an environment variable

```bash  
  export PPSSWWDD=yourRootPswd 
```

  More references: config/doNmapScan.sh
  By default, naabu is used to complete port scanning -stats=true to view the scanning progress
  Can I not scan Ports?
```bash
noScan=true ./scan4all -l list.txt -v
# nmap result default noScan=true 
./scan4all -l nmapRssuilt.xml -v
```

<img src="/static/nmap.gif" width="400">

- Fast 15000+ POC detection capabilities, PoCs include: 
  * nuclei POC
  ## Nuclei Templates Top 10 statistics

|    TAG    | COUNT |    AUTHOR     | COUNT |    DIRECTORY     | COUNT | SEVERITY | COUNT |  TYPE   | COUNT |
|-----------|-------|---------------|-------|------------------|-------|----------|-------|---------|-------|
| cve       |  1430 | daffainfo     |   631 | cves             |  1407 | info     |  1474 | http    |  3858 |
| panel     |   655 | dhiyaneshdk   |   584 | exposed-panels   |   662 | high     |  1009 | file    |    76 |
| edb       |   563 | pikpikcu      |   329 | vulnerabilities  |   509 | medium   |   818 | network |    51 |
| lfi       |   509 | pdteam        |   269 | technologies     |   282 | critical |   478 | dns     |    17 |
| xss       |   491 | geeknik       |   187 | exposures        |   275 | low      |   225 |         |       |
| wordpress |   419 | dwisiswant0   |   169 | misconfiguration |   237 | unknown  |    11 |         |       |
| exposure  |   407 | 0x_akoko      |   165 | token-spray      |   230 |          |       |         |       |
| cve2021   |   352 | princechaddha |   151 | workflows        |   189 |          |       |         |       |
| rce       |   337 | ritikchaddha  |   137 | default-logins   |   103 |          |       |         |       |
| wp-plugin |   316 | pussycat0x    |   133 | file             |    76 |          |       |         |       |

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
- Intelligently identify honeypots and skip Targets. This function is disabled by default. You can set EnableHoneyportDetection=true to enable
- Highly customizable: allow to define your own dictionary through config/config.json configuration, or control more details, including but not limited to: nuclei, httpx, naabu, etc.
- support HTTP Request Smuggling: CL-TE、TE-CL、TE-TE、CL_CL、BaseErr
  <img width="968" alt="image" src="https://user-images.githubusercontent.com/18223385/182503765-1307a634-61b2-4f7e-9631-a4184ec7ac25.png">

- Support via parameter Cookie='PHPSession=xxxx' ./scan4all -host xxxx.com, compatible with nuclei, httpx, go-poc, x-ray POC, filefuzz, http Smuggling
# work process

<img src="static/workflow.jpg">

# how to install
download from
<a href=https://github.com/GhostTroops/scan4all/releases>Releases</a>
```bash
go install github.com/GhostTroops/scan4all@2.8.9
scan4all -h
````
# how to use
- 1. Start Elasticsearch, of course you can use the traditional way to output, results
```bash
mkdir -p logs data
docker run --restart=always --ulimit nofile=65536:65536 -p 9200:9200 -p 9300:9300 -d --name es -v $PWD/logs:/usr/share/elasticsearch/logs -v $PWD /config/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml -v $PWD/config/jvm.options:/usr/share/elasticsearch/config/jvm.options -v $PWD/data:/ usr/share/elasticsearch/data hktalent/elasticsearch:7.16.2
# Initialize the es index, the result structure of each tool is different, and it is stored separately
./config/initEs.sh

# Search syntax, more query methods, learn Elasticsearch by yourself
http://127.0.0.1:9200/nmap_index/_doc/_search?q=_id:192.168.0.111
where 92.168.0.111 is the target to query

````
- Please install nmap by yourself before use
  <a href=https://github.com/GhostTroops/scan4all/discussions>Using Help</a>
```bash
go build
# Precise scan szUrl list UrlPrecise=true
UrlPrecise=true ./scan4all -l xx.txt
# Disable adaptation to nmap and use naabu port to scan its internally defined http-related Ports
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

# Q & A
- how use Cookie?
- libpcap related question

more see: <a href=https://github.com/GhostTroops/scan4all/discussions>discussions</a>

# References 
- https://www.77169.net/html/312916.html
- https://zhuanlan.zhihu.com/p/636131542
- https://github.com/GhostTroops/scan4all/blob/main/static/Installation.md
- https://github.com/GhostTroops/scan4all/blob/main/static/NicePwn.md
- https://github.com/GhostTroops/scan4all/blob/main/static/running.md
- https://www.google.com/search?client=safari&rls=en&q=%22hktalent%22+%22scan4all%22&ie=UTF-8&oe=UTF-8#ip=1

# Thanks Donors
- <a href=https://github.com/freeload101 target=_blank>@freeload101</a>
- <a href=https://github.com/b1win0y target=_blank>@b1win0y</a>
- <a href=https://github.com/BL4CKR4Y target=_blank>@BL4CKR4Y</a>

# Contributors
https://github.com/GhostTroops/scan4all/graphs/contributors

# Changelog
- 2023-10-01 Optimize support for nuclei@latest
- 2022-07-28 Added substr and aes_cbc dsl helper by me nuclei v2.7.7
- 2022-07-20 fix and PR nuclei #2301 Concurrent multi-instance bug
- 2022-07-20 add web cache vulnerability scanner
- 2022-07-19 PR nuclei #2308 add dsl function: substr aes_cbc
- 2022-07-19 Add dcom Protocol enumeration network interfaces
- 2022-06-30 Embedded integrated private version nuclei-templates A total of 3744 YAML POC; 1. Integrate Elasticsearch to store intermediate results 2. Embed the entire config directory into the program
- 2022-06-27 Optimize fuzzy matching to improve accuracy and robustness; integrate ksubdomain progress
- 2022-06-24 Optimize fingerprint algorithm; add workflow chart
- 2022-06-23 Added parameter ParseSSl to control the default of not deeply analyzing DNS information in SSL and not scanning DNS in SSL by default; Optimization: nmap does not automatically add .exe bug; Optimize the bug of cache files under Windows not optimizing the size
- 2022-06-22 Integrated weak password detection and password blasting for 11 protocols: ftp, mongodb, mssql, mysql, oracle, postgresql, rdp, redis, smb, ssh, telnet, and optimized support for plug-in password dictionary
- 2022-06-20 Integrate Subfinder, domain name blasting, startup parameter export EnableSubfinder=true, note that it is very slow after startup; automatic deep drilling of domain name information in the ssl certificate allows you to define your own dictionary through config/config.json configuration, or set related switch
- 2022-06-17 Optimize the situation where one domain name has multiple IPs. All IPs will be port scanned, and then follow the subsequent scanning process.
- 2022-06-15 This version adds several weblogic password dictionaries and webshell dictionaries obtained in past actual combat
- 2022-06-10 Complete the integration of the core, including of course the integration of the core template
- 2022-06-07 Add similarity algorithm to detect 404
- 2022-06-07 Added http url list precision scanning parameters, turned on according to the environment variable UrlPrecise=true

# Communication group (WeChat, QQ，Tg)
| Wechat | Or | QQchat | Or | Tg |
| --- |--- |--- |--- |--- |
|<img width=166 src=https://github.com/hktalent/scan4all/blob/main/static/wcq.JPG>||<img width=166 src=https://github.com/hktalent/scan4all/blob/main/static/qqc.jpg>||<img width=166 src=https://github.com/hktalent/scan4all/blob/main/static/tg.jpg>|


## 💖Star
[![Stargazers over time](https://starchart.cc/hktalent/scan4all.svg)](https://starchart.cc/hktalent/scan4all)

# Donation
| Wechat Pay | AliPay | Paypal | BTC Pay |BCH Pay |
| --- | --- | --- | --- | --- |
|<img src=https://raw.githubusercontent.com/hktalent/myhktools/main/md/wc.png>|<img width=166 src=https://raw.githubusercontent.com/hktalent/myhktools/main/md/zfb.png>|[paypal](https://www.paypal.me/pwned2019) **miracletalent@gmail.com**|<img width=166 src=https://raw.githubusercontent.com/hktalent/myhktools/main/md/BTC.png>|<img width=166 src=https://raw.githubusercontent.com/hktalent/myhktools/main/md/BCH.jpg>|

