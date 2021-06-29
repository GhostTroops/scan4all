Vscan
================================
Vscan 是一款为红队开发的简单、快速的跨平台打点扫描器。

#### 1.目标：翻版goby扫描器
[https://github.com/gobysec/Goby](https://github.com/gobysec/Goby)
goby是一款已经比较成熟的红队打点扫描器，我目前的开发目标是能达到其同样的效果，虽然有点重复造轮子的嫌疑，但是goby有个缺点是不开源，无法特别灵活的添加自己想要的东西


#### 2.端口扫描

[https://github.com/projectdiscovery/naabu](https://github.com/projectdiscovery/naabu)

一款扫描器必备的东西是端口扫描，虽然massscan和nmap是非常给力的端口扫描工具，要比其他端口扫描器好用，但是由于他们都是C语言开发的，想要集成到vscan里比较繁琐，所以我选择了大方向go语言的一款端口扫描器，他支持CONNECT、SYN扫描，C段扫描等功能，对于我们来说完全足够

端口扫描一般是作为输入的第一步，所以我们不需要指定太多默认参数，只需要修改一下输出即可
![](/img/vscan/2021-06-23-11-31-36.png)
我将Output的默认输出参数调整为ips_port.txt，输出格式为192.168.1.1:80，可以非常方便的读取并进行下一步扫描，同时，我们可以保留其他输入参数，保留原扫描器的功能


#### 3.服务识别
[https://github.com/projectdiscovery/httpx](https://github.com/projectdiscovery/httpx)
这是一款http服务快速识别扫描器
对于外网打点来说，最重要的就是web快速扫描，这款识别扫描器非常好用，可以快速识别网站的标题、网址、状态码、指纹等，还可以保留内容

同样的，我将它集成到vscan的pkg包里，并赋值一些默认参数，将端口扫描的结果ips_port.txt作为输入
![](/img/vscan/2021-06-23-11-40-15.png)

需要注意的是，由于httpx使用了retryablehttp库作为指纹识别，我们需要把retryablehttp库整个下载下来，方便后续的指纹添加,这里我添加了一个shiro指纹，可以快速识别服务器是否使用shiro
![](/img/vscan/2021-06-23-11-41-59.png)


#### 4.漏洞扫描（nday、0day自动利用）
我在pkg包里新建了一个exp版块，建立了一个入口函数check，以后其他所有nday也可以使用同样的入口，方便检测

![](/img/vscan/2021-06-23-11-43-50.png)

shiro exp内容：
包含CBC、GCM两种方式的检测，遍历测试一百多个key

漏洞扫描的过程我放到了指纹识别以后多线程并行进行，例如如果识别到使用了shiro服务，则调用shiro.Check
```
matches := r.wappalyzer.Fingerprint(resp.Headers, resp.Data)
for match := range matches {
    technologies = append(technologies, match)
    if match == "Shiro" {
        key := shiro.Check(URL.String())
        if key != ""{
            technologies = append(technologies, "key:"+key)
        }
    }
}
```
### 5.TO DO

1.加入智能后台弱口令扫描

2.加入其他nday

### 6.目前正在做的

1、如何最高效率获取后台地址

2、寻找识别模式来判断是否后台登录

3、构建后台登录通讯包

4、进行循环爆破操作

