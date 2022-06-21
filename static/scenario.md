
# 场景


## 外网场景

您需要自己收集目标的外网资产信息，包括资产的域名、C段、相关IP等，将资产汇总后去重保存于本地，然后使用scan4all进行快速的漏洞扫描。

```shell
scan4all -l input.txt -ceyeapi xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx -ceyedomain xxxxxx.ceye.io -csv -o output.csv
```
input.txt 内可以是多种格式，可以是URL、域名、C段、IP(URL地址不会进行端口扫描)

## 内网场景

直接使用 scan4all 对于B段的扫描速度非常慢（大量的端口扫描），建议使用 [fscan](https://github.com/shadow1ng/fscan) 先对内网进行B段IP存活探测，再将存活的IP列表导入 scan4all 进行扫描

```shell
scan4all -l ips.txt -ceyeapi xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx -ceyedomain xxxxxx.ceye.io -csv -o output.csv
```

## WAF场景

如遇到WAF封禁IP的情况，建议先对资产进行指纹识别，再对url地址进行POC检测。
这样至少能得到资产的指纹列表，不至于完全没有结果

1.
```shell
scan4all -l input.txt -np -csv -o output.csv
```

2.
```shell
scan4all -l urls.txt -ceyeapi xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx -ceyedomain xxxxxx.ceye.io -csv -o poc_output.csv
```