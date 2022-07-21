[![Tweet](https://img.shields.io/twitter/url/http/Hktalent3135773.svg?style=social)](https://twitter.com/intent/follow?screen_name=Hktalent3135773) [![Follow on Twitter](https://img.shields.io/twitter/follow/Hktalent3135773.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=Hktalent3135773) [![GitHub Followers](https://img.shields.io/github/followers/hktalent.svg?style=social&label=Follow)](https://github.com/hktalent/)
<p align="center">
   <a href="/README_EN.md">README_EN</a> •
   <a href="/static/Installation.md">编译/安装/运行</a> •
   <a href="/static/usage.md">参数说明</a> •
   <a href="/static/running.md">如何使用</a> •
   <a href="/static/scenario.md">使用场景</a> •
   <a href="/static/pocs.md">POC列表</a> •
   <a href="/static/development.md">自定义扫描</a> •
   <a href="/static/NicePwn.md">最佳实践</a>
</p>

# 特性

<h1 align="center">
<img width="928" alt="image" src="https://user-images.githubusercontent.com/18223385/175768227-098c779b-6c5f-48ee-91b1-c56e3daa9c87.png">
</h1>

- 什么是scan4all：集成vscan、nuclei、ksubdomain、subfinder等，充分自动化、智能化 
  并对这些集成对项目进行代码级别优化、参数优化，个别模块重写  
  原则上不重复造轮子，除非轮子bug、问题太多
- 跨平台：基于golang实现，轻量级、高度可定制、开源，支持Linux、windows、mac os等
- 支持【20】种密码爆破，支持自定义字典, 通过 "priorityNmap": true 开启 
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
  * SMB,同时检测 MS17-010（CVE-2017-0143、CVE-2017-0144、CVE-2017-0145、CVE-2017-0146、CVE-2017-0147、CVE-2017-0148）、SmbGhost（CVE-2020-0796）
  * Telnet
  * Snmp
  * Wap-wsp（Elasticsearch）
  * RouterOs
  * HTTP BasicAuth
  * Weblogic，同时通过enableNuclei=true开启nuclei，支持T3、IIOP等检测
  * Tomcat
  * Jboss
  * Winrm(wsman)
- 默认开启http密码智能爆破，需要http密码时才会自动启动，无需人工干预
- 检测系统是否存在nmap，存在通过 priorityNmap=true 启用nmap进行快速扫描，鉴于大多数人使用windows，默认关闭
  使用nmap的弊端：因为设置网络包过大会导致结果不全
  使用nmap另外需要将root密码设置到环境变量PPSSWWDD，更多参考config/doNmapScan.sh
  默认使用naabu完成端口扫描 -stats=true 可以查看扫描进度 
- 快速 15000+ POC 检测功能，PoCs包含：
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
    * vscan POC包含了：xray 2.0 300+ POC、 go POC等
  * scan4all POC  
  
- 支持7000+web指纹扫描、识别：
  * httpx指纹
  * vscan指纹
    * vscan指纹：包含 eHoleFinger、 localFinger等
  * scan4all指纹 
    
- 支持146种协议90000+规则port扫描
  * 依赖nmap支持的协议、指纹
- 快速HTTP敏感文件检测，可以自定义字典
- 登陆页面检测
- 支持多种类型的输入 - STDIN/HOST/IP/CIDR/URL/TXT
- 支持多种输出类型 - JSON/TXT/CSV/STDOUT
- 高度可集成：可配置将结果统一存储到 Elasticsearch【强烈推荐】
- 智能SSL分析：
  * 深入分析，自动关联SSL信息中域名的扫描，如*.xxx.com，并根据配置完成子域遍历，结果自动添加目标到扫描列表
  * 支持开启智能SSL信息中*.xx.com子域遍历功能， export EnableSubfinder=true，或者在配置文件中调整
- 自动识别域（DNS）关联多个IP的情况，并自动扫描关联的多个IP
- 智能处理： 
  * 1、当列表中多个域名的ip相同时，合并端口扫描，提高效率
  * 2、智能处理http异常页面、及指纹计算和学习
- 自动化供应链识别、分析和扫描
- 联动 python3 <a href=https://github.com/hktalent/log4j-scan>log4j-scan</a>
  * 该版本屏蔽你目标信息传递到 DNS Log Server 的bug，避免暴露漏洞
  * 增加了将结果发送到 Elasticsearch 的功能，便于批量、盲打
  * 未来有时间了再实现golang版本
- 智能识别蜜罐，并跳过目标，默认该功能是关闭的，可设置EnableHoneyportDetection=true开启
- 高度可定制：允许通过config/config.json配置定义自己的字典，或者控制更多细节，包含不限于:nuclei、httpx、naabu等

# 工作流程

<img src="static/workflow.jpg">

# 如何安装
```bash
go install github.com/hktalent/scan4all@2.5.9
scan4all -h
```
# 如何使用
- 1、启动 Elasticsearch, 当然你可以使用传统方式输出、结果
```bash
mkdir -p logs data
docker run --restart=always --ulimit nofile=65536:65536 -p 9200:9200 -p 9300:9300 -d --name es -v $PWD/logs:/usr/share/elasticsearch/logs -v $PWD/config/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml -v $PWD/config/jvm.options:/usr/share/elasticsearch/config/jvm.options  -v $PWD/data:/usr/share/elasticsearch/data  hktalent/elasticsearch:7.16.2
# 初始化es 索引,每种工具的结果结构不一样，分开存储
./config/initEs.sh

# 搜索语法，更多的查询方法，自己学 Elasticsearch
http://127.0.0.1:9200/nmap_index/_doc/_search?q=_id:192.168.0.111
其中92.168.0.111 是要查询的目标

```
- 使用前请自行安装nmap
<a href=https://github.com/hktalent/scan4all/discussions>使用帮助</a>
```bash
go build
# 精准扫描 url列表 UrlPrecise=true
UrlPrecise=true ./scan4all -l xx.txt
```

# Work Plan
- 整合 web-cache-vulnerability-scanner 实现HTTP smuggling走私、缓存中毒检测
- 联动 metasploit-framework，在系统已经安装好对前提条件下，配合tmux，并以 macos 环境为最佳实践完成联动
- 整合 更多 fuzzer <!-- gryffin -->,如 联动 sqlmap
- 整合 chromedp 实现对登陆页面截图，以及对纯js、js架构前端登陆页面进行检测、以及相应爬虫（敏感信息检测、页面爬取）
- 整合 nmap-go 提高执行效率
- 整合 ksubdomain 实现更快子域名爆破
- 整合 spider 以便发现更多漏洞
- 指纹半自动化学习，提高精准度

# 变更日志
- 2022-07-20 fix and PR nuclei <a href=https://github.com/projectdiscovery/nuclei/pull/2308>#2301</a> 并发多实例的bug
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