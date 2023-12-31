package go_utils

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

/*
le :en,fr,ko,ja
*/
func Fanyi4YoudaoPars(sT string, le string) string {
	szRst := ""
	var mD = map[string]any{
		"header": map[string]any{"fn": "auto_translation", "session": "", "user": ""},
		"type":   "plain", "model_category": "normal", "text_domain": "",
		"source": map[string]any{"lang": le, "text_list": []string{sT}}, "target": map[string]any{"lang": "zh"}}
	var data []byte
	if data1, err := json.Marshal(mD); nil == err {
		data = data1
	} else {
		return sT
	}
	DoUrlCbk4byte("https://transmart.qq.com/api/imt", data, map[string]string{
		"Accept":             "application/json, text/plain, */*",
		"Accept-Language":    "zh,en;q=0.9,zh-CN;q=0.8",
		"Connection":         "keep-alive",
		"Content-Type":       "application/json",
		"X-Requested-With":   "XMLHttpRequest",
		"DNT":                "1",
		"Origin":             "https://transmart.qq.com",
		"Referer":            "https://transmart.qq.com/zh-CN/index",
		"Sec-Fetch-Dest":     "empty",
		"Sec-Fetch-Mode":     "cors",
		"Sec-Fetch-Site":     "same-site",
		"User-Agent":         "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0",
		"sec-ch-ua-mobile":   "?0",
		"sec-ch-ua-platform": "macOS",
	}, func(resp *http.Response, szUrl string) {
		if data1, err := io.ReadAll(resp.Body); nil == err {
			var m = map[string]interface{}{}
			if Json.Unmarshal(data1, &m) == nil {
				szRst = GetJQ2Str(m, ".auto_translation[0]")
				if "" == szRst {
					szRst = Fanyi4YoudaoPars1(sT, le)
				}
			}
		} else {
			fmt.Println(err)
		}
	})
	return szRst
}

func Fanyi4YoudaoPars1(sT string, le string) string {
	szRst := ""
	x := "webdict"
	v := sT
	t := v + x
	time1 := len(v+x) % 10
	s := fmt.Sprintf("%x", md5.Sum([]byte(t)))
	tm1 := fmt.Sprintf("%d", time1)
	s = "web" + v + tm1 + "Mk6hqtUp33DGGtoS63tTJbMUYjRrG1Lu" + s
	s = fmt.Sprintf("%x", md5.Sum([]byte(s)))
	data := []byte("q=" + url.QueryEscape(v) + "&le=" + le + "&t=" + tm1 + "&client=web&sign=" + s + "&keyfrom=" + x)
	DoUrlCbk4byte("https://dict.youdao.com/jsonapi_s?doctype=json&jsonversion=4", data, map[string]string{
		"Accept":             "application/json, text/plain, */*",
		"Accept-Language":    "zh,en;q=0.9,zh-CN;q=0.8",
		"Connection":         "keep-alive",
		"Content-Type":       "application/x-www-form-urlencoded",
		"DNT":                "1",
		"Origin":             "https://www.youdao.com",
		"Referer":            "https://www.youdao.com/",
		"Sec-Fetch-Dest":     "empty",
		"Sec-Fetch-Mode":     "cors",
		"Sec-Fetch-Site":     "same-site",
		"User-Agent":         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
		"sec-ch-ua":          `"Chromium";v="118", "Google Chrome";v="118", "Not=A?Brand";v="99"`,
		"sec-ch-ua-mobile":   "?0",
		"sec-ch-ua-platform": "macOS",
	}, func(resp *http.Response, szUrl string) {
		if data1, err := io.ReadAll(resp.Body); nil == err {
			var m = map[string]interface{}{}
			if Json.Unmarshal(data1, &m) == nil {
				szRst = GetJQ2Str(m, ".fanyi.tran")
				if "" == szRst {
					if wt, ok := m["web_trans"]; ok {
						if m1, ok := wt.(map[string]interface{}); ok {
							wt2 := m1["web-translation"]
							if a1, ok := wt2.([]interface{}); ok && 0 < len(a1) {
								if m2, ok := a1[0].(map[string]interface{}); ok {
									if a2, ok := m2["trans"]; ok {
										if a3, ok := a2.([]interface{}); ok && 1 < len(a3) {
											if m4, ok := a3[0].(map[string]interface{}); ok {
												szRst = fmt.Sprintf("%s", m4["value"])
											}
										}
									}
								}
							}
						}
					}
					//szRst = GetJQ2Str(m, ".web_trans.web-translation[0].trans[1].value")
				}
				//fmt.Println(string(data1))
			}
		} else {
			fmt.Println(err)
		}
	})
	return szRst
}

/*
翻译中文
*/
func Fanyi4Youdao(sT string) string {
	return Fanyi4YoudaoPars(sT, "en")
}
