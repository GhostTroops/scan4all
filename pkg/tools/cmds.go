package tools

import (
	"fmt"
	"github.com/GhostTroops/scan4all/pkg/common"
	"github.com/GhostTroops/scan4all/pkg/option"
	. "github.com/GhostTroops/scan4all/pkg/utils"
	util "github.com/hktalent/go-utils"
	"log"
	"regexp"
	"strings"
)

/*
如果 i 是 []string 或者 string 就转换 输入out
*/
func DoAorS(i interface{}, out chan *string, rTrimX *regexp.Regexp, szTag string) {
	if a, ok := i.([]interface{}); ok {
		for _, x := range a {
			if util.TestRepeat(x, szTag) {
				continue
			}
			x1 := rTrimX.ReplaceAllString(x.(string), "")
			out <- &x1
		}
	} else if s, ok := i.(string); ok {
		if util.TestRepeat(s, szTag) {
			return
		}
		s = rTrimX.ReplaceAllString(s, "")
		out <- &s
	}
}

/*
nmap -sC -sV -p- -T4 -Pn

*/
// ssh -p 22 -C root@xxx "curl https://www.google.com"
// 检查避免重复
func NoRepeat(i chan *string, key string, wg *util.SizedWaitGroup) chan *string {
	var out = make(chan *string)
	var szQuery = ""
	var nType = GetType(key)
	switch key {
	case Ipgs:
		szQuery = "domain:\"%s\""
	case Tlsx:
		szQuery = "domain:\"%s\""
	}
	util.WaitFunc4Wg(wg, func() {
		for x := range i {
			*x = strings.TrimSpace(*x)
			if "" == *x {
				continue
			}
			if util.TestRepeat(*x, key, NoRepeat) {
				continue
			}
			sI := GetInput(*x, nType)
			if o := common.Query4Tags(fmt.Sprintf(szQuery, sI), key); nil != o {
				// 结果传入 下一 层任务
				log.Println("skip", key, sI)
				continue
			}
			out <- x
		}
		close(i)
	})
	return out
}

func DoNodeCmd(cNode1 *option.Cmd, iptTmp1 chan *string, wg *util.SizedWaitGroup) {
	util.WaitFunc4Wg(wg, func() {
		DoCmdNode(cNode1, iptTmp1)
	})
}

/*
执行 下一节点 任务
*/
func DoNext(curCmd *option.Cmd, m *map[string]interface{}, wg *util.SizedWaitGroup) {
	nq := curCmd.NextQueryPath
	if nil == nq {
		return
	}
	for _, x := range curCmd.Next {
		if cNode := option.GetCmdNode4key(x); nil != cNode {
			var szQnext = nq.Default
			var iptTmp = make(chan *string)

			if s, ok := nq.QueryPath[x]; ok {
				szQnext = s
			}
			DoNodeCmd(cNode, iptTmp, wg)
			for _, x1 := range strings.Split(szQnext, ",") {
				DoAorS(util.GetJQ(m, x1), iptTmp, TrimXx, cNode.Name)
			}
		}
	}
}

/*
"gopoc","nuclei","filefuzz"
所有的输入流 输出都是 json
需要为个别 非 json 输出处理
*/
func DoCmdNode(cmd1 *option.Cmd, i chan *string) bool {
	bRst := false
	var wg = util.NewSizedWaitGroup(0)
	switch cmd1.Name {
	case Ipgs, Ksubdomain, Httpx, Tlsx, Nuclei: // 输入命令行 管道流
		common.DoCmd4Cbk(cmd1.Cmd, func(s *string) {
			if nil == s {
				return
			}
			var m = map[string]interface{}{}
			if nil == util.Json.Unmarshal([]byte(*s), &m) {
				m = *util.RmMap(&m, cmd1.ResultRmKey)
				if Tlsx == cmd1.Name { // 去重复 迭代
					for _, x := range strings.Split(cmd1.SelfDo, ",") {
						DoAorS(util.GetJQ(m, x), i, TrimXx, cmd1.Name)
					}
				}
				log.Println(m)
				m["tags"] = cmd1.Name
				m["id"] = util.GetSha1(cmd1.Cmd, m)
				if s5, ok := m["host"]; ok {
					m["domain"] = s5
					delete(m, "host")
				}
				common.Save2RmtDb(m, cmd1.Name, ".id")
				util.WaitFunc4Wg(&wg, func() {
					DoNext(cmd1, &m, &wg)
				})
			}
		}, NoRepeat(i, cmd1.Name, &wg))
		bRst = true
		break
	case Nmap, Masscan:
	case Gopoc:
	case Filefuzz:

	}
	wg.Wait()
	return bRst
}

func DoCmds(i chan *string, n int) {
	if 0 < len(option.Cmds) {
		start := option.Cmds[n]
		if DoCmdNode(start, i) {
			return
		}
		//for x := range i {
		//	switch start.Name {
		//	case "ipgs":
		//	case "ksubdomain":
		//	case "masscan":
		//	case "nmap":
		//	case "httpx":
		//	case "tlsx":
		//	case "nuclei":
		//	case "gopoc":
		//	case "filefuzz":
		//
		//	}
		//}
	}
}
