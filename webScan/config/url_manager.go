package Configs

import (
	"fmt"
	"net/url"
	"strings"
)

func Get_Url(urls string, port_split bool) string {
	if !strings.HasPrefix(urls, "http") {
		urls = "http://" + urls
	}
	urls = strings.Trim(urls, " ")
	if strings.HasPrefix(urls, "http") {

		url_tmp, err := url.Parse(urls)
		if err != nil {
			fmt.Println("url.Parse err", err)
		}

		if port_split == true {
			if url_tmp.Port() != "" {
				url_tmp_host := strings.Split(url_tmp.Host, ":")[0]
				return url_tmp_host
			} else {
				return url_tmp.Host
			}

		} else {
			return url_tmp.Host
		}

	}
	return "nil"
}
