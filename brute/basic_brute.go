package brute

import (
	"fmt"
	"github.com/veo/vscan/pkg"
)

func Basic_brute(url string) (username string, password string) {
	var basicusers = []string{"admin", "root"}
	if req, err := pkg.HttpRequsetBasic("asdasdascsacacs", "adcadcadcadcadcadc", url, "HEAD", "", false, nil); err == nil {
		if req.StatusCode == 401 {
			for useri := range basicusers {
				for passi := range top100pass {
					if req2, err2 := pkg.HttpRequsetBasic(basicusers[useri], top100pass[passi], url, "HEAD", "", false, nil); err2 == nil {
						if req2.StatusCode == 200 || req2.StatusCode == 403 {
							pkg.BurteLog(fmt.Sprintf("Found vuln basic password|%s:%s|%s\n", basicusers[useri], top100pass[passi], url))
							return basicusers[useri], top100pass[passi]
						}
					}
				}
			}
		}
	}
	return "", ""
}
