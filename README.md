[![Tweet](https://img.shields.io/twitter/url/http/Hktalent3135773.svg?style=social)](https://twitter.com/intent/follow?screen_name=Hktalent3135773) [![Follow on Twitter](https://img.shields.io/twitter/follow/Hktalent3135773.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=Hktalent3135773) [![GitHub Followers](https://img.shields.io/github/followers/hktalent.svg?style=social&label=Follow)](https://github.com/hktalent/)
<p align="center">
   <a href="/README_EN.md">README_EN</a>
   <a href="/static/Installation.md">编译/安装/运行</a> •
   <a href="/static/usage.md">参数说明</a> •
   <a href="/static/running.md">如何使用</a> •
   <a href="/static/scenario.md">使用场景</a> •
   <a href="/static/pocs.md">POC列表</a> •
   <a href="/static/development.md">自定义扫描</a>
   <a href="/static/NicePwn.md">最佳实践</a>
</p>

# 特性

<h1 align="center">
<img width="928" alt="image" src="https://user-images.githubusercontent.com/18223385/175768227-098c779b-6c5f-48ee-91b1-c56e3daa9c87.png">
</h1>

- 轻量级、高度可定制、开源、跨平台使用，支持Linux、windows、mac os等
- 支持18种密码爆破，支持自定义字典
  rdp,ssh,rsh-spx,mysql,mssql,oracle,postgresql,redis,ftp,mongodb,smb,telnet,snmp,wap-wsp（Elasticsearch）、http、weblogic、tomcat、jboss
- 默认开启http密码智能爆破，需要http密码时才会自动启动，无需人工干预
- 默认检测系统是否存在nmap，存在优先则使用nmap进行快速扫描
  弊端：因为设置网络包过大会导致结果不全 
  另外需要将root密码设置到环境变量PPSSWWDD，更多参考config/doNmapScan.sh
- 快速15000+POC检测功能（nuclei POC + vscan POC + scan4all的POC）
- 支持7000+web指纹扫描、识别（httpx指纹 + vscan指纹 + scan4all的指纹）
- 支持146种协议90000+规则port扫描（依赖nmap支持的协议、指纹，号称超过146种协议的都是"Tree New Bee(树新蜂)"）
- 快速http敏感文件检测，可以自定义字典
- 登陆页面检测
- 支持多种类型的输入 - STDIN/HOST/IP/CIDR/URL/TXT
- 支持多种输出类型 - JSON/TXT/CSV/STDOUT
- 高度可集成：可配置将结果统一存储到 Elasticsearch【强烈推荐】
- 智能SSL分析：
  深入分析，自动关联SSL信息中域名的扫描，如*.xxx.com，并根据配置完成子域遍历，结果自动添加目标到扫描列表
  支持开启智能SSL信息中*.xx.com子域遍历功能， export EnableSubfinder=true，或者在配置文件中调整
- 自动识别域（DNS）关联多个IP的情况，并自动扫描关联的多个IP
- 智能预处理：当列表中多个域名的ip相同时，合并端口扫描，提高效率
- 自动化供应链识别、分析和扫描
- 高度可定制：允许通过config/config.json配置定义自己的字典，或者控制更多细节，包含不限于:nuclei、httpx、naabu等

# 工作流程

<img src="static/workflow.jpg">

# 如何安装
```bash
go install github.com/hktalent/scan4all@2.4.8
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

# 变更日志
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