package brute

import "fmt"

func File_fuzz(url string) (path string) {
	for urli := range filedic {
		if req, err := httpRequset(url+filedic[urli], "GET", ""); err == nil {
			if req.StatusCode == 200 {
				fmt.Printf("fuzz_file|%s", filedic[urli])
				fmt.Println()
				return filedic[urli]
			}
		}
	}
	return ""
}
