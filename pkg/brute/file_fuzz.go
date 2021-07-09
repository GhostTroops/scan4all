package brute

import "fmt"

func File_fuzz(url string) (path []string) {
	if _, err := httpRequset(url, "GET", ""); err == nil {
		for urli := range filedic {
			if req2, err := httpRequset(url+filedic[urli], "GET", ""); err == nil {
				fmt.Println(req2.StatusCode)
				if req2.StatusCode == 200 {
					path = append(path, url+filedic[urli])
				}
			}
		}
	}
	return path
}
