package brute

func File_fuzz(url string) (path []string) {
	if _, err := httpRequset(url, "HEAD", ""); err == nil {
		for urli := range filedic {
			if req2, err := httpRequset(url+filedic[urli], "HEAD", ""); err == nil {
				if req2.StatusCode != 404 {
					path = append(path, url+filedic[urli])
				}
			}
		}
	}
	return path
}
