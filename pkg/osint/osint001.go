package osint

import (
	_ "embed"
	"fmt"
	util1 "github.com/hktalent/go-utils"
	"github.com/hktalent/scan4all/lib/util"
	"io"
	"net/http"
	"sort"
	"strings"
)

// https://github.com/thewhiteh4t/nexfil/raw/main/url_store.json

//go:embed url_store.json
var testData string
var mTest = []map[string]string{}

func init() {
	util.RegInitFunc(func() {
		util1.Json.Unmarshal([]byte(testData), &mTest)
	})
}

// allow_redirects=False
func Alt(resp *http.Response, szCheck string) bool {
	return resp.StatusCode == 200
}

// allow_redirects=True
func Method(resp *http.Response, szCheck string) bool {
	return resp.StatusCode != 404
}

// allow_redirects=true
func Sub(resp *http.Response, szCheck string) bool {
	return szCheck == resp.Request.URL.String()
}

// allow_redirects=True
func String(resp *http.Response, szCheck string) bool {
	if resp.StatusCode != 404 {
		// 200, 301, 302, 403, 405, 410, 418, 500
		if 0 <= sort.SearchInts([]int{200, 301, 302, 403, 405, 410, 418, 500}, resp.StatusCode) {
			if data, err := io.ReadAll(resp.Body); nil == err && 0 < len(data) {
				return -1 == strings.Index(string(data), szCheck)
			}
		}
	}
	return false
}

// allow_redirects=False
func Redirect(resp *http.Response, szCheck string) bool {
	return resp.Header.Get("Location") == resp.Request.URL.String()
}

// allow_redirects=True
func Api(resp *http.Response, szCheck string) bool {
	if resp.StatusCode != 404 {
		if data, err := io.ReadAll(resp.Body); nil == err && 0 < len(data) {
			var m1 = map[string]interface{}{}
			if nil == util1.Json.Unmarshal(data, &m1) {
				for _, x := range strings.Split("results,users,username", ",") {
					if "" != fmt.Sprintf("%v", util1.GetJson4Query(m1, "."+x)) {
						return true
					}
				}
			}
		}
	}
	return false
}

func DoLog(s string) {}

// https://github.com/thewhiteh4t/nexfil/blob/main/nexfil.py
func DoOsint(s string) {
	for _, x := range mTest {
		szUrl := fmt.Sprintf(x["url"], s)
		var szTest, szData = "", ""
		if s1, ok := x["test"]; ok {
			szTest = s1
		}
		if s1, ok := x["data"]; ok {
			szData = s1
		}

		cl1 := util1.PipE.GetClient(nil)
		cl1.CheckRedirect = nil // allow_redirects=True
		var respTrue, respFalse *http.Response
		switch szTest {
		case "method":
			util1.PipE.DoGetWithClient(cl1, szUrl, "GET", nil, func(resp *http.Response, err error, szU string) {
				respTrue = resp
			})
			if Method(respTrue, szData) {
				DoLog(szUrl)
			}
		case "string":
			util1.PipE.DoGetWithClient(cl1, szUrl, "GET", nil, func(resp *http.Response, err error, szU string) {
				respTrue = resp
			})
			if String(respTrue, szData) {
				DoLog(szUrl)
			}
		case "redirect":
			util1.PipE.DoGetWithClient(cl1, szUrl, "GET", nil, func(resp *http.Response, err error, szU string) {
				respTrue = resp
			})
			if Redirect(respTrue, szData) {
				DoLog(szUrl)
			}
		case "api":
			util1.PipE.DoGetWithClient(cl1, szUrl, "GET", nil, func(resp *http.Response, err error, szU string) {
				respTrue = resp
			})
			if Api(respTrue, szData) {
				DoLog(szUrl)
			}
		case "sub":
			util1.PipE.DoGetWithClient(cl1, szUrl, "GET", nil, func(resp *http.Response, err error, szU string) {
				respTrue = resp
			})
			if Sub(respTrue, szData) {
				DoLog(szUrl)
			}

		case "alt":
			util1.PipE.DoGetWithClient(nil, szUrl, "GET", nil, func(resp *http.Response, err error, szU string) {
				respFalse = resp
			})
			if Alt(respFalse, szData) {
				DoLog(szUrl)
			}
		default:
			util1.PipE.DoGetWithClient(cl1, szUrl, "GET", nil, func(resp *http.Response, err error, szU string) {
				respTrue = resp
			})
			if 0 <= sort.SearchInts([]int{200, 301, 302, 403, 405, 410, 418, 500}, respTrue.StatusCode) {
				if _, ok := x["test"]; !ok {

				} else if szTest == "url" {
				} else if szTest == "subdomain" {
				}
			} else if respTrue.StatusCode == 404 && szTest == "method" {
				if Method(respTrue, szData) {
					DoLog(szUrl)
				}
			}
		}
	}
}
