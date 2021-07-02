Vscan
================================
Vscan 是一款为红队开发的简单、快速的跨平台打点扫描器。

### 1.目标：翻版goby扫描器
[https://github.com/gobysec/Goby](https://github.com/gobysec/Goby)
goby是一款已经比较成熟的红队打点扫描器，我目前的开发目标是能达到其同样的效果，虽然有点重复造轮子的嫌疑，但是goby有个缺点是不开源，无法特别灵活的添加自己想要的东西


### 2.功能
##### 2.1 端口扫描

[https://github.com/projectdiscovery/naabu](https://github.com/projectdiscovery/naabu)

一款扫描器必备的东西是端口扫描，虽然massscan和nmap是非常给力的端口扫描工具，要比其他端口扫描器好用，但是由于他们都是C语言开发的，想要集成到vscan里比较繁琐，所以我选择了大方向go语言的一款端口扫描器，他支持CONNECT、SYN扫描，C段扫描等功能，对于我们来说完全足够

端口扫描一般是作为输入的第一步，所以我们不需要指定太多默认参数，只需要修改一下输出即可
![](/img/vscan/2021-06-23-11-31-36.png)
我将Output的默认输出参数调整为ips_port.txt，输出格式为192.168.1.1:80，可以非常方便的读取并进行下一步扫描，同时，我们可以保留其他输入参数，保留原扫描器的功能


##### 2.2 服务识别
[https://github.com/projectdiscovery/httpx](https://github.com/projectdiscovery/httpx)
这是一款http服务快速识别扫描器
对于外网打点来说，最重要的就是web快速扫描，这款识别扫描器非常好用，可以快速识别网站的标题、网址、状态码、指纹等，还可以保留内容

同样的，我将它集成到vscan的pkg包里，并赋值一些默认参数，将端口扫描的结果ips_port.txt作为输入
![](/img/vscan/2021-06-23-11-40-15.png)

需要注意的是，由于httpx使用了retryablehttp库作为指纹识别，我们需要把retryablehttp库整个下载下来，方便后续的指纹添加,这里我添加了一个shiro指纹，可以快速识别服务器是否使用shiro
![](/img/vscan/2021-06-23-11-41-59.png)


##### 2.3 漏洞扫描（nday、0day自动利用）
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

##### 2.4 智能后台弱口令扫描，中间件弱口令扫描

弱口令其实是打点一个较为关键的部分，需要人工去抓包使用工具爆破

这里我完成了最简单的没有使用验证码，没有使用vue等前端框架的后台智能爆破，可以一定量的减少手工时间，加快打点速度

内置了两个账号 admin/test，密码为top100，如果成功识别后台会标记Login_Page，成功构建登录包会自动爆破出密码

如：

`http://xxx.xxx.xxx.xxx:8080 [302,200] [登录 - 后台] [Shiro,key:Z3VucwAAAAAAAAAAAAAAAA==,Java,Login_Page,爆破成功，账号密码 admin:123456] [http://xxx.xxx.xxx.xxx:8080/login;JSESSIONID=8417fe14-f529-46a7-a67e-bbe96429cbd0]`
### 3.演示
```
root@xxx:~/vscan# ./vscan  -iL ../urlx.txt -top-ports top-100
[INF] Running SYN scan with root privileges
http://xxx.xxx.xxx.xxx [200] [xxx集团] [Nginx]
http://xxx.xxx.xxx.xxx [302,200] [后台管理] [jQuery,Nginx,Font Awesome,animate.css,Lightbox,Bootstrap] [http://xxx.xxx.xxx.xxx/web/index.html]
http://xxx.xxx.xxx.xxx:9999 [302,200] [安全入口校验失败] [Nginx] [http://xxx.xxx.xxx.xxx:9999/login]
http://xxx.xxx.xxx.xxx [200] [没有找到站点] [Nginx]
https://xxx.xxx.xxx.xxx [302,404] [404 Not Found] [Nginx] [http://xxx.xxx.xxx.xxx/login;JSESSIONID=9af94a66-6099-40c2-8b0f-8a9d7d5e1c8d]
http://xxx.xxx.xxx.xxx [403] [403 - 禁止访问: 访问被拒绝。] [IIS,Windows Server]
http://xxx.xxx.xxx.xxx:8888 [302,200] [安全入口校验失败] [Nginx] [http://xxx.xxx.xxx.xxx:8888/login]
http://xxx.xxx.xxx.xxx:8080 [400] [Bad Request] [Microsoft HTTPAPI]
http://xxx.xxx.xxx.xxx:8888 [426] []
https://xxx.xxx.xxx.xxx [200] [xxx集团【免费】工商注册] [Nginx,OWL Carousel,jQuery,animate.css]
http://xxx.xxx.xxx.xxx:8080 [302,200] [登录 - 后台] [Shiro,key:Z3VucwAAAAAAAAAAAAAAAA==,Java,Login_Page,爆破成功，账号密码 admin:123456] [http://xxx.xxx.xxx.xxx:8080/login;JSESSIONID=8417fe14-f529-46a7-a67e-bbe96429cbd0]
http://xxx.xxx.xxx.xxx:8888 [302,200] [后台管理系统] [Microsoft ASP.NET,IIS,Windows Server,Login_Page] [http://xxx.xxx.xxx.xxx:8888/Login]
http://xxx.xxx.xxx.xxx [302,200] [登录后台] [Login_Page,Font Awesome,Bootstrap,jQuery,Nginx,Ionicons] [http://xxx.xxx.xxx.xxx:80/site/login]
https://xxx.xxx.xxx.xxx [200] [xxx集团【免费】工商注册] [animate.css,Nginx,OWL Carousel,jQuery]
http://xxx.xxx.xxx.xxx:81 [302,200] [xxx邮箱管理后台] [Nginx,PHP,Login_Page] [http://xxx.xxx.xxx.xxx:81/Center/Index/login]
http://xxx.xxx.xxx.xxx:81 [200] [用户登录-端午管理后台] [Login_Page]
http://xxx.xxx.xxx.xxx [302,200] [xxx娱乐-后台管理系统] [Apache,Windows Server,OpenSSL,PHP,Login_Page] [http://xxx.xxx.xxx.xxx:80/Public.login.do]
http://xxx.xxx.xxx.xxx:8000 [200] [后台登陆] [Windows Server,Login_Page,Microsoft ASP.NET,IIS]
http://xxx.xxx.xxx.xxx:9999 [200] [phpMyAdmin] [PHP,Debian,Apache,phpMyAdmin,MySQL,Login_Page]
https://xxx.xxx.xxx.xxx [200] [xxx集团【免费】工商注册] [animate.css,Nginx,OWL Carousel,jQuery]
https://xxx.xxx.xxx.xxx [302,200] [后台管理登录 - 中国同学录] [Nginx,PHP,Bootstrap,jQuery,Login_Page,Font Awesome] [https://xxx.xxx.xxx.xxx:443/login]
http://xxx.xxx.xxx.xxx [200] [后台登录 - xxx管理系统] [animate.css,Bootstrap,jQuery,Nginx,Login_Page,Font Awesome]
https://xxx.xxx.xxx.xxx [302,200] [登录后台] [Bootstrap,jQuery,Ionicons,Login_Page,Font Awesome,Nginx] [https://xxx.xxx.xxx.xxx:443/site/login]
https://xxx.xxx.xxx.xxx [302,200] [登录后台] [Font Awesome,Nginx,Bootstrap,jQuery,Ionicons,Login_Page] [https://xxx.xxx.xxx.xxx:443/site/login]
https://xxx.xxx.xxx.xxx [200] [xxx集团【免费】工商注册] [Nginx,animate.css,OWL Carousel,jQuery]
https://xxx.xxx.xxx.xxx [302,301,302,200] [xxx娱乐] [Windows Server,OpenSSL,Apache,PHP,Login_Page] [https://wap.mfzz2088.com/Public.login.do]
http://xxx.xxx.xxx.xxx [302,200] [登录后台] [Nginx,Bootstrap,jQuery,Ionicons,Login_Page,Font Awesome] [http://xxx.xxx.xxx.xxx:80/site/login]
http://xxx.xxx.xxx.xxx [302,200] [登录后台] [Nginx,Font Awesome,Bootstrap,jQuery,Ionicons,Login_Page] [http://xxx.xxx.xxx.xxx:80/site/login]
http://xxx.xxx.xxx.xxx [302,200] [登录后台] [Nginx,Font Awesome,Bootstrap,jQuery,Ionicons,Login_Page] [http://xxx.xxx.xxx.xxx:80/site/login]
https://xxx.xxx.xxx.xxx [302,200] [登录后台] [Nginx,Bootstrap,jQuery,Ionicons,Login_Page,Font Awesome] [https://xxx.xxx.xxx.xxx:443/site/login]
https://xxx.xxx.xxx.xxx [302,200] [登录后台] [Nginx,Bootstrap,jQuery,Ionicons,Login_Page,Font Awesome] [https://xxx.xxx.xxx.xxx:443/site/login]
http://xxx.xxx.xxx.xxx:8080 [302,200] [xxx后台管理系统] [Login_Page,Shiro,key:kPH+bIxk5D2deZiIxcaaaA==,Java,Google Font API] [http://xxx.xxx.xxx.xxx:8080/login.jsp;JSESSIONID=ae74b4b5-f290-4660-8d25-05595861325b]
```

### 4.TO DO

1.加入weblogic，tomcat等中间件的爆破

2.加入其他nday

### 5.目前正在做的

1、如何识别中间件

2、加入中间件爆破板块