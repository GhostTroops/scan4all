<p align="center">
   <a href="/README_EN.md">README_EN</a>
   <a href="/static/Installation.md">编译/安装/运行</a> •
   <a href="/static/usage.md">参数说明</a> •
   <a href="/static/running.md">如何使用</a> •
   <a href="/static/scenario.md">使用场景</a> •
   <a href="/static/pocs.md">POC列表</a> •
   <a href="/static/development.md">自定义扫描</a>
</p>

# 特性

<h1 align="center">
<img width="966" alt="image" src="https://user-images.githubusercontent.com/18223385/175191886-aec31972-d81b-46f4-b6ac-70debd2508e7.png">
</h1>

- 快速端口扫描，指纹检测功能
- 快速登录密码爆破功能
- 快速POC检测功能
- 快速敏感文件检测
- 轻量级、开源、跨平台使用
- 支持多种类型的输入 - STDIN/HOST/IP/CIDR/URL/TXT
- 支持多种输出类型 - JSON/TXT/CSV/STDOUT

## 由配置文件、环境变量控制的新特性
- 带有上下文路径的url列表，启用精确扫描 UrlPrecise=true ./main -l xx.txt
- 开启智能子域遍历， export EnableSubfinder=true
- 自动识别域（DNS）关联多个IP的情况，并自动扫描关联的多个IP
- 预处理，当列表中多个域名的ip相同时，合并端口扫描，提高效率
- 深入分析，自动关联扫描：自动获取ssl中的域名信息，如*.xxx.com，并配置允许自动子域遍历，子域遍历自动完成，添加目标到扫描列表
- 当输入目标（target）为ip时，所有域名、指纹信息、历史端口信息都会从51pwn云自动关联，并进行处理（云服务功能需要授权）
- 自动化供应链分析和扫描，需要授权才能使用
- 允许通过config/config.json配置定义自己的字典，或者设置相关的开关，可以在这里定义nuclei、httx、naabu的几个Options

# 工作流程

<img src="static/workflow.jpg">

- 0.【智能子域名爆破】集成Subfinder,当通过 export EnableSubfinder=true 开启后，ssl证书中的域名信息包含"*."开头时自动启动子域名遍历
- 1.【端口扫描】集成Nuclei官方产品naabu ( > 2.1k)
- 2.【服务识别】naabu调用系统安装的nmap，请先自行安装nmap
  * 2.1 nmap扫描后，自动启动集成当kscan进行弱密码检测，密码字典支持自定义字典，可以通过config.json进行配置
- 3.【网页扫描】集成httpx（ > 3.2k），Nuclei官方出品
  * 3.1 【指纹识别】集成优化的EHole（ > 1.4k）
- 4.【漏洞扫描】
  * 集成核（ > 8.6k）+核模板（4.5k优化版，https://github.com/hktalent/nuclei-templates）
  * 集成 xray 2.0 (6.9k)，共 354 个 POC
  * 集成 vscan 实现了8个fuzz组件，同时实现了集成14类常用组件的漏洞检测

# 如何安装
```bash
go install github.com/hktalent/scan4all@2.3.0
scan4all -h
```
# 如何使用
使用前请自行安装nmap
<a href=https://github.com/hktalent/scan4all/discussions>使用帮助</a>
```bash
go build
# 精准扫描 url列表 UrlPrecise=true
UrlPrecise=true ./scan4all -l xx.txt
```

# 变更日志
- 2022-06-20 集成Subfinder，域名爆破，启动参数导出EnableSubfinder=true，注意启动后很慢； ssl证书中域名信息的自动深度钻取
  允许通过 config/config.json 配置定义自己的字典，或设置相关开关
- 2022-06-17 优化一个域名多个IP的情况，所有IP都会被端口扫描，然后按照后续的扫描流程
- 2022-06-15 此版本增加了过去实战中获得的几个weblogic密码字典和webshell字典
- 2022-06-10 完成核的整合，当然包括核模板的整合
- 2022-06-07 添加相似度算法来检测 404
- 2022-06-07 增加http url列表精准扫描参数，根据环境变量UrlPrecise=true开启