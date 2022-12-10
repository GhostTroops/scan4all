package util

import (
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
)

func GetIp() map[string]interface{} {
	szUrl := "https://apis.map.qq.com/ws/location/v1/ip"
	c := GetClient(szUrl)
	c.UseHttp2 = false
	var m1 map[string]interface{}
	c.DoGetWithClient4SetHd(c.GetClient(nil), szUrl, "POST", strings.NewReader("key="+url.QueryEscape("IVOBZ-QNW6P-SUKDY-LFQSE-LUFCJ-3CFUE")+"&sig=afebe5ad5227ec75a1f3d8b97f888cda"), func(r *http.Response, err1 error, szU string) {
		defer r.Body.Close()
		if data, err := ioutil.ReadAll(r.Body); nil == err {

			if nil == json.Unmarshal(data, &m1) {
				log.Printf("%+v", m1)
			}
		}
	}, func() map[string]string {
		return map[string]string{"User-Agent": "Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0", "Accept": "*/*"}
	}, false)
	//if r, err := DoPost(szUrl, map[string]string{"User-Agent": "Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0", "Accept": "*/*"}, strings.NewReader("key="+url.QueryEscape("IVOBZ-QNW6P-SUKDY-LFQSE-LUFCJ-3CFUE")+"&sig=afebe5ad5227ec75a1f3d8b97f888cda")); nil == err && r != nil {
	//	defer r.Body.Close()
	//	if data, err := ioutil.ReadAll(r.Body); nil == err {
	//		var m1 map[string]interface{}
	//		if nil == json.Unmarshal(data, &m1) {
	//			log.Printf("%+v", m1)
	//			return m1
	//		}
	//	}
	//}
	return m1
}
