<p align="center">开源、轻量、快速、跨平台 的网站漏洞扫描工具，帮助您快速检测网站安全隐患。</p>

<p align="center">
<a href="https://github.com/hktalent/scan4all/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://github.com/hktalent/scan4all"><img alt="Release" src="https://img.shields.io/badge/LICENSE-BSD-important"></a>
<a href="https://github.com/hktalent/scan4all/releases"><img src="https://img.shields.io/github/release/hktalent/scan4all"></a>
<a href="https://github.com/hktalent/scan4all/releases"><img src="https://img.shields.io/github/downloads/hktalent/scan4all/total?color=blueviolet"></a>
</p>

<p align="center">
  <a href="/static/Installation.md">编译/安装/运行</a> •
  <a href="/static/usage.md">参数说明</a> •
  <a href="/static/running.md">使用方法</a> •
  <a href="/static/scenario.md">使用场景</a> •
  <a href="/static/pocs.md">POC列表</a> •
  <a href="/static/development.md">自定义扫描器</a>
</p>

# Features

<h1 align="center">
  <img src="static/scan4all-run.png" alt="scan4all" width="850px"></a>
  <br>
</h1>

- Fast port scan, fingerprint detection function
- Fast login password blasting function
- Fast POC detection function
- Fast sensitive file detection
- Lightweight, open source, cross-platform use
- Supports multiple types of input - STDIN/HOST/IP/CIDR/URL/TXT
- Supports multiple types of output - JSON/TXT/CSV/STDOUT
## New features controlled by configuration files, environment variables
- url list with context path, enable precise scan UrlPrecise=true ./main -l xx.txt
- Enable smart subdomain traversal, export EnableSubfinder=true
- Automatically identify the situation that a domain (DNS) is associated with multiple IPs, and automatically scan the associated multiple IPs
- Preprocessing, when multiple domain names in the list have the same ip, port scans are merged to improve efficiency
- In-depth analysis, automatic correlation scan: automatically obtain domain name information in ssl, in the case of *.xxx.com, and configured to allow automatic subdomain traversal, the subdomain traversal will be automatically completed, and the target will be added to the scan list
- When the input target (target) is ip, all domain names, fingerprint information, historical port information will be automatically associated from the 51pwn cloud, and processed (the cloud service function requires authorization)
- Automated supply chain analysis and scanning, which requires authorization to use
- Allows to define your own dictionary through config/config.json configuration, or set related switches, you can define several Options for nuclei, httx, naabu here
# Implementation process
- 0. [Subdomain] integrates Subfinder, export EnableSubfinder=true starts, automatically drills deep into the domain name information in the ssl certificate
- 1. [Port Scanning] Integrate naabu (2.1k), the official product of Nuclei, the famous name Dingding
- 2. [Service Identification] naabu calls the nmap installed by the system, please install nmap yourself first
- 3. [Fingerprint recognition] nmap + integrated and optimized EHole (1.4k), and will continue to integrate more fingerprint recognition later
- 4. [Web Scanning] Integrated httpx (3.2k), officially produced by Nuclei, the famous name Dingding
- 5. [Vulnerability Scanning]
    * Integrated nuclei (8.6k) + nuclei-templates (4.5k optimized version, https://github.com/hktalent/nuclei-templates)
    * Integrated xray 2.0 (6.9k), a total of 354 POCs
    * scan4all itself implements 8 fuzz components, and at the same time implements vulnerability detection that integrates 14 types of common components
# How Install
```bash
go install github.com/hktalent/scan4all@2.1.5
scan4all -h
```
# How use
Please install nmap by yourself before use
```bash
go build -o scan4all main.go
# Precise scanning UrlPrecise=true
UrlPrecise=true ./scan4all -l xx.txt
```

# changelog
- 2022-06-20 集成了Subfinder，做子域名爆破，启动参数export EnableSubfinder=true，注意，启动后很慢；自动深度钻取ssl证书中的域名信息
             允许通过config/config.json配置定义自己的字典，或设置相关开关
- 2022-06-17 优化一个域名多个ip的情况，所有ip都会被端口扫描，然后走后续的扫描流程
- 2022-06-15 该版本增加了若干过去实战中获得的weblogic密码字典，以及webshell字典
- 2022-06-10 完成nuclei的集成，当然也包含nuclei模版的集成
- 2022-06-07 增加了相似度算法对404检测
- 2022-06-07 增加了http url清单精准扫描参数,基于环境变量UrlPrecise=true 开启

