package brute

func File_fuzz(url string) (path []string) {
	if reqdir, err := httpRequset(url+"/url_not_support/", "HEAD", ""); err == nil {
		if reqfile, err := httpRequset(url+"/file_not_support.html", "HEAD", ""); err == nil {
			if reqdir.StatusCode == 403 || reqfile.StatusCode == 403 {
				for urli := range filedic {
					if req2, err := httpRequset(url+filedic[urli], "HEAD", ""); err == nil {
						if (req2.StatusCode == 200 || req2.StatusCode == 401) && req2.ContentLength != reqfile.ContentLength {
							path = append(path, filedic[urli])
						}
					}
				}
			} else {
				for urli := range filedic {
					lastword := filedic[urli][len(filedic[urli])-1:]
					if req2, err := httpRequset(url+filedic[urli], "HEAD", ""); err == nil {
						if lastword == "/" && (req2.StatusCode == 403 || req2.StatusCode == 200 || req2.StatusCode == 401) && req2.ContentLength != reqdir.ContentLength {
							path = append(path, filedic[urli])
						} else if (req2.StatusCode == 200 || req2.StatusCode == 401) && req2.ContentLength != reqfile.ContentLength {
							path = append(path, filedic[urli])
						}
					}
				}
			}
			if len(path) > 15 {
				path = nil
			}
		}
	}
	return path
}
