package brute

func File_fuzz(url string) (path []string) {

	if _, err := httpRequset(url, "HEAD", ""); err == nil {
		for urli := range filedic {
			lastword := filedic[urli][len(filedic[urli])-1:]
			if req2, err := httpRequset(url+filedic[urli], "HEAD", ""); err == nil {
				if lastword == "/" && (req2.StatusCode == 200 || req2.StatusCode == 403) {
					path = append(path, url+filedic[urli])
				} else if req2.StatusCode == 200 {
					path = append(path, url+filedic[urli])
				}
			}
		}
	}
	return path
}
