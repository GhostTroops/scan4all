# 使用方法介绍

## 输入

```shell    
scan4all -host 127.0.0.1
```
会对 127.0.0.1 进行http常用端口扫描，扫描完端口后对端口地址进行检测

```shell    
scan4all -host http://127.0.0.1:7001
```
不会对 127.0.0.1 进行端口扫描，而是直接对 http://127.0.0.1:7001 地址进行检测

```shell    
scan4all -host 192.168.1.1/24
```
对 192.168.1.1/24 C段进行端口扫描，扫描完端口后对端口地址进行检测

```shell    
scan4all -l ips.txt
```
对 ips.txt 内的 ip/域名/c段/url地址 进行逐行检测(如果有url地址，则不会进行端口扫描)


```shell    
echo 127.0.0.1|scan4all
```
可以使用管道进行输入并扫描

## 选择扫描方式

```shell    
scan4all -host 127.0.0.1 -s SYN
```
SYN扫描速度更快，但需要root权限 (不使用此参数，默认进行SYN扫描)


## 端口选择

```shell    
scan4all -host 127.0.0.1 -p 7001,7002
```
对 127.0.0.1 的7001,7002端口进行检测

```shell    
scan4all -host 127.0.0.1 -top-Ports 1000
scan4all -host 127.0.0.1 -top-Ports http
```
对 127.0.0.1 进行 NmapTop1000 端口进行检测 (不使用此参数，默认进行http常用端口扫描)




## 使用DNSLOG功能

```shell    
scan4all -host 127.0.0.1 -ceyeapi xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx -ceyedomain xxxxxx.ceye.io
```
使用DNSLOG功能可以更好的进行POC检测，有些POC的检测要用到DNSLOG功能

## 输出/导出功能

```shell    
scan4all -host 127.0.0.1 -json -o 1.json
```
输出json格式的结果，并且输出到1.json文件中。端口扫描结果保存在port.1.json中


```shell    
scan4all -host 127.0.0.1 -csv -o 1.csv
```
输出csv格式的结果，并且输出到1.csv文件中。端口扫描结果保存在port.1.csv中


## 只做端口扫描和指纹识别，不检测POC

```shell
scan4all -host 127.0.0.1 -np
```

## 取消颜色输出

```shell    
scan4all -host 127.0.0.1 -no-color
```

## 设置线程和线程速率

```shell    
scan4all -host 127.0.0.1 -c 25 -rate 1000
```

## 代理功能

```shell    
scan4all -host 127.0.0.1 -proxy socks5://127.0.0.1:1080
```

## 排除CDN

```shell    
scan4all -host www.google.com -ec
```

##  直接使用nmap扫描结果，跳过内部端口扫描

```shell    
scan4all -l nmapResult.xml -v
```

## 其他

见 [Usage](/static/usage.md)