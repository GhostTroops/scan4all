<p align="center">
   <a href="/static/Installation.md">Compile/Install/Run</a> •
   <a href="/static/usage.md">Parameter Description</a> •
   <a href="/static/running.md">How To</a> •
   <a href="/static/scenario.md">Scenario</a> •
   <a href="/static/pocs.md">POC List</a> •
   <a href="/static/development.md">Custom Scanner</a>
</p>

# Features

<h1 align="center">
<img width="966" alt="image" src="https://user-images.githubusercontent.com/18223385/175191886-aec31972-d81b-46f4-b6ac-70debd2508e7.png">
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
go install github.com/hktalent/scan4all@2.2.3
scan4all -h
```
# How use
Please install nmap by yourself before use
```bash
go build -o scan4all main.go
# or
go build
# Precise scanning UrlPrecise=true
UrlPrecise=true ./scan4all -l xx.txt
```

# changelog
- 2022-06-20 Integrated Subfinder, domain name blasting, startup parameter export EnableSubfinder=true, note that it is very slow after startup; automatic deep drilling of domain name information in ssl certificate
  Allows to define your own dictionary through config/config.json configuration, or set related switches
- 2022-06-17 Optimize the case of multiple IPs in one domain name, all IPs will be port scanned, and then follow the subsequent scanning process
- 2022-06-15 This version adds several weblogic password dictionaries and webshell dictionaries obtained in actual combat in the past
- 2022-06-10 Complete the integration of nuclei, including the integration of nuclei templates of course
- 2022-06-07 Added similarity algorithm to detect 404
- 2022-06-07 Added the http url list precise scan parameter, which is enabled based on the environment variable UrlPrecise=true
