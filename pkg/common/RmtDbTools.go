package common

import (
	"bytes"
	"fmt"
	util "github.com/hktalent/go-utils"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var (
	UserAgent = "Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0"
	DbUrl     = ""
	GKey      = ""
	Headers   = map[string]string{
		"user-agent": UserAgent,
		"H2H":        GKey,
	}
	szTags = ""
	AddStr = "%2B"
)

func ClsMap(m *map[string]interface{}) *map[string]interface{} {
	var a []string
	for k, v := range *m {
		if s, ok := v.(string); ok && (s == "" || s == ",") {
			a = append(a, k)
		}
	}
	for _, x := range a {
		delete(*m, x)
	}
	return m
}

func init() {
	if s := os.Getenv("Tags"); "" != s {
		szTags += "," + s
	}
	util.RegInitFunc(func() {
		DbUrl = util.GetVal("indexServer")
		GKey = util.GetVal("GKey")
	})
}
func CloneObj(o map[string]interface{}) *map[string]interface{} {
	if data, err := util.Json.Marshal(o); nil == err {
		var o1 = map[string]interface{}{}
		if nil == util.Json.Unmarshal(data, &o1) {
			return &o1
		}
	}
	return &o
}

// +tags:ipgs +domain:/.*butian.*/
// +tags:ipgs +domain:/.*iifl.*/
// companyInfo.organizationName:"IIFL"
func SaveIpgs(m *map[string]interface{}) {
	//m := CloneObj(*m1)
	//lc := util.GetLock("SaveIpgs" + util.GetSha1(m)).Lock()
	//defer lc.Unlock()
	if nil != m {
		m = ClsMap(m)
		if 3 > len(*m) {
			return
		}
		szT := "ipgs,tls,ssl" + szTags
		var a []string
		for _, x := range []string{"domain", "host", "url"} {
			if s, ok := (*m)[x]; ok {
				a = append(a, s.(string))
			}
		}
		a = append(a, szT)
		(*m)["id"] = util.GetSha1(strings.Join(a, "_"))
		Save2RmtDb(m, szT, ".id")
	}
}

func Query4Tags(sQ, szTag string) *map[string]interface{} {
	a := QueryRmtDbBBSec(fmt.Sprintf(`%stags:%s %s%s`, AddStr, szTag, AddStr, sQ), 1)
	if nil == a || 0 == len(a) {
		return nil
	}
	return a[0]
}

func QueryIpgs(s string) *map[string]interface{} {
	a := QueryRmtDbBBSec(fmt.Sprintf(`%stags:ipgs %sdomain:"%s"`, AddStr, AddStr, s), 1)
	if nil == a || 0 == len(a) {
		return nil
	}
	return a[0]
}

func QueryIpgsCmp(s string) *map[string]interface{} {
	a := QueryRmtDbBBSec(fmt.Sprintf(`%stags:ipgs %sdomain:"%s %scompanyInfo.localityName:/.*/"`, AddStr, AddStr, s, AddStr), 1)
	if nil == a || 0 == len(a) {
		return nil
	}
	return a[0]
}

func SaveRmtDb4Any(iName, tags, qid, qitem string, data1 []byte) {
	util.DoUrlCbk4byte(fmt.Sprintf("%s/doBlv?t=%s&qitem=%s&tags=%s&qid=%s", DbUrl, iName, qitem, tags, qid),
		data1,
		Headers,
		func(resp *http.Response, szUrl string) {
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
		})
}

//var ct = make(chan struct{}, 32)

func Save2RmtDb(data interface{}, tags, qid string) {
	//ct <- struct{}{}
	//defer func() {
	//	<-ct
	//}()
	if data1, err := util.Json.Marshal(data); nil == err {
		util.DoUrlCbk4byte(fmt.Sprintf("%s/doBlv?t=BBSec&tags=%s&qid=%s", DbUrl, url.QueryEscape(tags), url.QueryEscape(qid)),
			data1,
			Headers,
			func(resp *http.Response, szUrl string) {
				defer resp.Body.Close()
				io.Copy(io.Discard, resp.Body)
				//log.Println("ok", tags, qid)
			})
	}
}
func QueryRmtDbBBSec(s string, n int) []*map[string]interface{} {
	return QueryRmtDb(s, "BBSec", n)
}
func QueryRmtDb(s, dbName string, n int) []*map[string]interface{} {
	var r []*map[string]interface{}
	util.DoUrlCbk(fmt.Sprintf("%s/getH2h?q=%s&i=%s&f=0&s=%d", DbUrl, url.QueryEscape(s), dbName, n),
		"",
		Headers,
		func(resp *http.Response, szUrl string) {
			defer resp.Body.Close()
			if data, err := io.ReadAll(resp.Body); nil == err {
				util.ReadStream4Line(bytes.NewReader(data), func(s *string) {
					if nil == s {
						return
					}
					var r2 = map[string]interface{}{}
					if nil == util.Json.Unmarshal([]byte(*s), &r2) {
						r = append(r, &r2)
					}
				})
			}
		})
	if nil == r || 0 == len(r) {
		return nil
	}
	return r
}
