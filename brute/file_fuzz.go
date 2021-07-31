package brute

var dirpath []string
var filepath []string

func File_fuzz(url string) (path []string) {
	if req, err := httpRequset(url+"/url_not_support/", "HEAD", ""); err == nil {
		if req.StatusCode == 404 {
			for urli := range filedic {
				lastword := filedic[urli][len(filedic[urli])-1:]
				if req2, err := httpRequset(url+filedic[urli], "HEAD", ""); err == nil {
					if lastword == "/" && (req2.StatusCode == 302 || req2.StatusCode == 403 || req2.StatusCode == 200) {
						path = append(path, url+filedic[urli])
					} else if req2.StatusCode == 200 {
						path = append(path, url+filedic[urli])
					}
				}
			}
		} else if req.StatusCode == 200 || req.StatusCode == 302 {
			for urli := range filedic {
				lastword := filedic[urli][len(filedic[urli])-1:]
				if req2, err := httpRequset(url+filedic[urli], "HEAD", ""); err == nil {
					if lastword == "/" {
						dirpath = append(dirpath, url+filedic[urli])
					} else {
						filepath = append(filepath, url+filedic[urli])
					}
					if lastword == "/" && (req2.StatusCode == 403) {
						path = append(path, url+filedic[urli])
					} else if req2.StatusCode == 200 {
						path = append(path, url+filedic[urli])
					}
				}
			}
			if len(filepath) == len(path) {
				path = nil
			}
		} else if req.StatusCode == 403 {
			for urli := range filedic {
				if req2, err := httpRequset(url+filedic[urli], "HEAD", ""); err == nil {
					if req2.StatusCode == 200 {
						path = append(path, url+filedic[urli])
					}
				}
			}

		} else {
			for urli := range filedic {
				lastword := filedic[urli][len(filedic[urli])-1:]
				if req2, err := httpRequset(url+filedic[urli], "HEAD", ""); err == nil {
					if lastword == "/" && (req2.StatusCode == 302 || req2.StatusCode == 403 || req2.StatusCode == 200) {
						path = append(path, url+filedic[urli])
					} else if req2.StatusCode == 200 {
						path = append(path, url+filedic[urli])
					}
				}
			}
		}
	}
	return path
}
