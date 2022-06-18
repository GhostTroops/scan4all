<h1 align="center">
  <img src="static/logo.png" alt="vscan" width="200px"></a>
  <br>
</h1>
<p align="center">开源、轻量、快速、跨平台 的网站漏洞扫描工具，帮助您快速检测网站安全隐患。</p>

<p align="center">
<a href="https://github.com/veo/vscan/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://github.com/veo/vscan"><img alt="Release" src="https://img.shields.io/badge/LICENSE-BSD-important"></a>
<a href="https://github.com/veo/vscan/releases"><img src="https://img.shields.io/github/release/veo/vscan"></a>
<a href="https://github.com/veo/vscan/releases"><img src="https://img.shields.io/github/downloads/veo/vscan/total?color=blueviolet"></a>
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
  <img src="static/vscan-run.png" alt="vscan" width="850px"></a>
  <br>
</h1>

- 快速的端口扫描、指纹探测功能
- 快速的登录密码爆破功能
- 快速的POC检测功能
- 快速的敏感文件检测功能
- 轻量、开源、跨平台使用
- 支持多种类型的输入 - **STDIN/HOST/IP/CIDR/URL/TXT**
- 支持多种类型的输出 - **JSON/TXT/CSV/STDOUT**

# 站在巨人肩膀上、扫描流程（顺序）
- 【端口扫描]集成了naabu（2.1k），大名顶顶的nuclei官方出品
- 【web扫描】集成了httpx（3.2k）,大名顶顶的nuclei官方出品
- 【指纹识别】集成、并优化了EHole（1.4k）
- 【漏洞扫描】
   * （分支https://github.com/hktalent/vscan ）集成了nuclei（8.6k）+ nuclei-templates(4.5k优化版本，https://github.com/hktalent/nuclei-templates)
   * 集成了xray 2.0（6.9k）,共354个POC
- vscan自身实现了8个fuzz组件，同时实现集成了14类常见组件的漏洞检测

# How use
```bash
go build -o vscan main.go
# 精准扫描 UrlPrecise=true
UrlPrecise=true ./main -l xx.txt
```

# changelog
- 2022-06-17 优化一个域名多个ip的情况，所有ip都会被端口扫描，然后走后续的扫描流程
- 2022-06-15 该版本增加了若干过去实战中获得的weblogic密码字典，以及webshell字典
- 2022-06-10 完成nuclei的集成，当然也包含nuclei模版的集成
- 2022-06-07 增加了相似度算法对404检测
- 2022-06-07 增加了http url清单精准扫描参数,基于环境变量UrlPrecise=true 开启

# Licenses

本工具仅面向合法授权的企业安全建设行为，在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，作者将不承担任何法律及连带责任。

在使用本工具前，请您务必审慎阅读、充分理解各条款内容，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。 除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。 
