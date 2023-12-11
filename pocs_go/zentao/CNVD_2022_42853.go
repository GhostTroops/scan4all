package zentao

import (
	"github.com/GhostTroops/scan4all/lib/util"
	"strings"
)

// zentao/user-login.html SQL注入
func CNVD_2022_42853(u string) bool {
	payload := "account='"
	header := make(map[string]string)
	header["Referer"] = u + "/zentao/user-login.html"
	if response, err := util.HttpRequset(u+"/zentao/user-login.html", "POST", payload, false, header); err == nil {
		if response.StatusCode == 200 && strings.Contains(response.Body, "You have an error in your SQL syntax;") {
			util.SendLog(response.RequestUrl, "CNVD_2022_42853", "Found vuln zentao CNVD-2022-42853", payload)
			return true
		}
	}
	return false
}
