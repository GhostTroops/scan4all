
# 场景

## WAF场景

如遇到WAF封禁IP的情况，建议先对资产进行指纹识别，再对url地址进行POC检测。
这样至少能得到资产的指纹列表，不至于完全没有结果

1.
```shell
./vscan -l input.txt -np -csv -o output.csv
```

2.
```shell
./vscan -l urls.txt -ceyeapi xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx -ceyedomain xxxxxx.ceye.io -csv -o poc_output.csv
```