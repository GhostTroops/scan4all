package brute

import (
	"fmt"
	"github.com/veo/vscan/pkg"
)

func Basic_brute(url string) (username string, password string) {
	if req, err := pkg.HttpRequsetBasic("asdasdascsacacs", "adcadcadcadcadcadc", url, "HEAD", "", false, nil); err == nil {
		if req.StatusCode == 401 {
			for useri := range usernames {
				for passi := range top100pass {
					if req2, err2 := pkg.HttpRequsetBasic(usernames[useri], top100pass[passi], url, "HEAD", "", false, nil); err2 == nil {
						if req2.StatusCode == 200 || req2.StatusCode == 403 {
							fmt.Printf("basic-brute-sucess|%s:%s|%s\n", usernames[useri], top100pass[passi], url)
							return usernames[useri], top100pass[passi]
						}
					}
				}
			}
		}
	}
	return "", ""
}
