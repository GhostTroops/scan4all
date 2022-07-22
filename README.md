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
    *rsh-spx
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
  export PPSSWWDD=yourRootPswd
  More references: config/doNmapScan.sh
  By default, naabu is used to complete port scanning -stats=true to view the scanning progress
  Can I not scan ports?
```bash
noScan=true ./scan4all -l list.txt -v
````
- Fast 15000+ POC detection capabilities, PoCs include: 
  * nuclei POC
  #### Nuclei Templates Top 10 statistics

|    TAG    | COUNT |    AUTHOR     | COUNT |    DIRECTORY     | COUNT | SEVERITY | COUNT |  TYPE   | COUNT |
|-----------|-------|---------------|-------|------------------|-------|----------|-------|---------|-------|
| cve       |  1263 | daffainfo     |   605 | cves             |  1257 | info     |  1351 | http    |  3516 |
| panel     |   586 | dhiyaneshdk   |   502 | exposed-panels   |   595 | high     |   930 | file    |    76 |
| lfi       |   482 | pikpikcu      |   320 | vulnerabilities  |   483 | medium   |   750 | network |    50 |
| xss       |   426 | pdteam        |   268 | technologies     |   266 | critical |   426 | dns     |    17 |
| wordpress |   399 | geeknik       |   187 | exposures        |   254 | low      |   209 |         |       |
| exposure  |   353 | dwisiswant0   |   169 | misconfiguration |   206 | unknown  |     6 |         |       |
| cve2021   |   311 | 0x_akoko      |   152 | token-spray      |   206 |          |       |         |       |
| rce       |   308 | princechaddha |   147 | workflows        |   187 |          |       |         |       |
| wp-plugin |   295 | pussycat0x    |   127 | default-logins   |    99 |          |       |         |       |
| tech      |   282 | gy741         |   124 | file             |    76 |          |       |         |       |
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
docker run --restart=always --ulimit nofile=65536:65536 -p 9200:9200 -p 9300:9300 -d --name es -v $PWD/logs:/usr/share/elasticsearch/logs -v $PWD /config/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml -v $PWD/config/jvm.options:/usr/share/elasticsearch/config/jvm.options -v $PWD/data:/ usr/share/elasticsearch/data hktalent/elasticsearch:7.16.2
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
- 2022-07-20 fix and PR nuclei <a href

# Donation
| Wechat Pay | AliPay | Paypal | BTC Pay |BCH Pay |
| --- | --- | --- | --- | --- |
|<img src=https://github.com/hktalent/myhktools/blob/master/md/wc.png>|<img width=166 src=https://github.com/hktalent/myhktools/blob/master/md/zfb.png>|[paypal](https://www.paypal.me/pwned2019) **miracletalent@gmail.com**|<img width=166 src=https://github.com/hktalent/myhktools/blob/master/md/BTC.png>|<img width=166 src=https://github.com/hktalent/myhktools/blob/master/md/BCH.jpg>|