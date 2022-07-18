[![Tweet](https://img.shields.io/twitter/url/http/Hktalent3135773.svg?style=social)](https://twitter.com/intent/follow?screen_name=Hktalent3135773) [![Follow on Twitter](https://img.shields.io/twitter/follow/Hktalent3135773.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=Hktalent3135773) [![GitHub Followers](https://img.shields.io/github/followers/hktalent.svg?style=social&label=Follow)](https://github.com/hktalent/)
<p align="center">
   <a href="/README_EN.md">README_EN</a> •
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

- Lightweight, highly customizable, open source, cross-platform use, supports Linux, windows, mac os, etc.
- Support 18 kinds of password blasting, support custom dictionary
  rdp,ssh,rsh-spx,mysql,mssql,oracle,postgresql,redis,ftp,mongodb,smb,telnet,snmp,wap-wsp(Elasticsearch),http,weblogic,tomcat,jboss
- By default, http password intelligent blasting is enabled, and it will be automatically activated when an http password is required, without manual intervention
- By default, whether there is nmap in the system is detected, and nmap is used for fast scanning if it exists first
  By default, naabu is used to complete port scanning -stats=true to view the scanning progress
  Disadvantages: The result is incomplete because the network package is set too much
  In addition, you need to set the root password to the environment variable PPSSWWDD, more refer to config/doNmapScan.sh
- Fast 15000+ POC detection function ( nuclei POC + vscan POC + scan4all POC )
  vscan POC includes: xray 2.0 300+ POC, go POC, etc.
- Support 7000+web fingerprint scanning and identification (httpx fingerprint + vscan fingerprint + scan4all fingerprint)
  vscan fingerprint: including eHoleFinger, localFinger, etc.
- Supports 146 protocols and 90000+ rule port scanning (depending on the protocols and fingerprints supported by nmap, it is claimed that more than 146 protocols are "Tree New Bee (Tree New Bee)")
- Fast http sensitive file detection, you can customize the dictionary
- Landing page detection
- Supports multiple types of input - STDIN/HOST/IP/CIDR/URL/TXT
- Supports multiple output types - JSON/TXT/CSV/STDOUT
- Highly integratable: Configurable unified storage of results to Elasticsearch [strongly recommended]
- Smart SSL Analysis:
  In-depth analysis, automatically correlate the scanning of domain names in SSL information, such as *.xxx.com, and complete subdomain traversal according to the configuration, and the result will automatically add the target to the scanning list
  Support to enable *.xx.com subdomain traversal function in smart SSL information, export EnableSubfinder=true, or adjust in the configuration file
- Automatically identify the case of multiple IPs associated with a domain (DNS), and automatically scan the associated multiple IPs
- Smart processing:
  1. When the IPs of multiple domain names in the list are the same, merge port scanning to improve efficiency
  2. Intelligently handle http abnormal pages, and fingerprint calculation and learning
- Automated supply chain identification, analysis and scanning
- Highly customizable: allow to define your own dictionary through config/config.json configuration, or control more details, including but not limited to: nuclei, httpx, naabu, etc.

# work process

<img src="static/workflow.jpg">

# how to install
```bash
go install github.com/hktalent/scan4all@2.4.8
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
````

# Changelog
- 2022-06-30 Embedded integrated private version nuclei-templates with a total of 3744 YAML POCs; 1. Integrate Elasticsearch to store intermediate results 2. Embed the entire config directory into the program
- 2022-06-27 Optimize fuzzy matching, improve accuracy and robustness; integrate ksubdomain progress
- 2022-06-24 Optimize fingerprint algorithm; add workflow flow chart
- 2022-06-23 Added parameter ParseSSl to control the default not to deeply analyze DNS information in SSL, and not to scan dns in SSL by default; optimization: nmap does not automatically add .exe bug; optimize the bug that the cache file is not optimized in size under windows
- 2022-06-22 Integrate 11 protocols for weak password detection and password blasting: ftp, mongodb, mssql, mysql, oracle, postgresql, rdp, redis, smb, ssh, telnet, and optimize support for plug-in password dictionaries
- 2022-06-20 Integrate Subfinder, domain name blasting, start parameter export EnableSubfinder=true, note that it is very slow after startup; automatic deep drilling of domain name information in ssl certificate
  Allows to define your own dictionary through config/config.json configuration, or set related switches
- 2022-06-17 Optimize the case of multiple IPs in one domain name, all IPs will be port scanned, and then follow the subsequent scanning process
- 2022-06-15 This version adds several weblogic password dictionaries and webshell dictionaries obtained in the past actual combat
- 2022-06-10 Complete the integration of the core, including the integration of the core template of course
- 2022-06-07 Add similarity algorithm to detect 404
- 2022-06-07 Added the http url list precise scanning parameter, which is enabled according to the environment variable UrlPrecise=true


# Donation
| Wechat Pay | AliPay | Paypal | BTC Pay |BCH Pay |
| --- | --- | --- | --- | --- |
|<img src=https://github.com/hktalent/myhktools/blob/master/md/wc.png>|<img width=166 src=https://github.com/hktalent/myhktools/blob/master/md/zfb.png>|[paypal](https://www.paypal.me/pwned2019) **miracletalent@gmail.com**|<img width=166 src=https://github.com/hktalent/myhktools/blob/master/md/BTC.png>|<img width=166 src=https://github.com/hktalent/myhktools/blob/master/md/BCH.jpg>|