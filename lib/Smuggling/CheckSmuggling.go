package Smuggling

import (
	"github.com/hktalent/scan4all/lib/socket"
	"github.com/hktalent/scan4all/lib/util"
)

// 接口定义
type Smuggling interface {
	CheckResponse(body string) bool
	GetPayloads() *[]string
	GetTimes() int
	GetVulType() string
}

var payload = []Smuggling{&ClTe{}, &TeCl{}, &TeTe{}}

func checkSmuggling4Poc(ClTePayload *[]string, nTimes int, r1 *Smuggling, r *socket.CheckTarget) {
	for _, x := range *ClTePayload {
		s := r.SendOnePayload(x, r.UrlPath, r.HostName, nTimes)
		if (*r1).CheckResponse(s) {
			// send result
			util.SendAnyData(&util.SimpleVulResult{
				Url:     r.UrlRaw,
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
  https://hackerone.com/reports/1630668
  https://github.com/nodejs/llhttp/blob/master/src/llhttp/http.ts#L483
  1、每个目标的登陆页面只做一次检测，也就是发现你登陆页面的路径可以做一次检测
  2、每个目标相同上下文的页面只做一次检测，爬虫发现的不同上下文各做一次检测
  szBody 是为了 相同url 相同payload 的情况下，只发一次请求，进行多次判断而设计，Smuggling 的场景通常不存在

 做一次 http
	util.PocCheck_pipe <- util.PocCheck{
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
				x1 := socket.NewCheckTarget(szUrl, "tcp", 3)
				defer x1.Close()
				checkSmuggling4Poc(j.GetPayloads(), j.GetTimes(), &j, x1)
			} else {
				j.CheckResponse(szBody)
			}
		}(x, szUrl)
	}
}
