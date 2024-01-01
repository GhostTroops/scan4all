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
func DoAorS(i interface{}, out chan *string, rTrimX *regexp.Regexp, szTag string) bool {
	bRst := false
	if a, ok := i.([]interface{}); ok {
		for _, x := range a {
			if util.TestRepeat(x, szTag) {
				continue
			}
			x1 := rTrimX.ReplaceAllString(x.(string), "")
			bRst = true
			out <- &x1
		}
	} else if s, ok := i.(string); ok {
		if util.TestRepeat(s, szTag) {
			return bRst
		}
		s = rTrimX.ReplaceAllString(s, "")
		bRst = true
		out <- &s
	}
	return bRst
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
			if util.TestRepeat(*x, key) {
				continue
			}
			sI := GetInput(*x, nType)
			if o := common.Query4Tags(fmt.Sprintf(szQuery, sI), key); nil != o {
				// 结果传入 下一 层任务
				log.Println("skip", key, sI)
				continue
			}
			//log.Println("start <- ", *x)
			out <- x
			//log.Println("end <- ", *x)
		}
	})
	return out
}

func DoNodeCmd(cNode1 *option.Cmd, iptTmp1 chan *string, wg *util.SizedWaitGroup) {
	util.WaitFunc4Wg(wg, func() {
		DoCmdNode(cNode1, iptTmp1, wg)
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
	for _, x7 := range curCmd.Next {
		func(x string) {
			util.WaitFunc4Wg(wg, func() {
				if cNode := option.GetCmdNode4key(x); nil != cNode {
					var szQnext = nq.Default
					if s, ok := nq.QueryPath[x]; ok {
						szQnext = s
					}
					if "" == szQnext {
						return
					}
					var iptTmp = make(chan *string)
					DoNodeCmd(cNode, iptTmp, wg)
					// 捕获 输入
					for _, x1 := range strings.Split(szQnext, ",") {
						s12 := util.GetJQ(m, x1)
						if nil == s12 {
							continue
						}
						DoAorS(s12, iptTmp, TrimXx, cNode.Name)
					}
					// 运行到这里，理论上 iptTmp 中数据已经清空
					close(iptTmp)
				}
			})
		}(x7)

	}
}

/*
"gopoc","nuclei","filefuzz"
所有的输入流 输出都是 json
需要为个别 非 json 输出处理
*/
func DoCmdNode(cmd1 *option.Cmd, i2 chan *string, wg *util.SizedWaitGroup) bool {
	bRst := false
	i1 := NoRepeat(i2, cmd1.Name, wg)
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
						DoAorS(util.GetJQ(m, x), i1, TrimXx, cmd1.Name)
					}
				}
				if cmd1.Name == Httpx {
					log.Println(m)
				}

				m["tags"] = cmd1.Name
				m["id"] = util.GetSha1(cmd1.Cmd, m)
				if s5, ok := m["host"]; ok {
					m["domain"] = s5
					delete(m, "host")
				}
				common.Save2RmtDb(m, cmd1.Name, ".id")
				util.WaitFunc4Wg(wg, func() {
					DoNext(cmd1, &m, wg) // "httpx","ipgs","masscan","ksubdomain"
				})
			}
		}, i1, wg)
		bRst = true
		break
	case Nmap, Masscan:
	case Gopoc:
	case Filefuzz:

	}
	return bRst
}

func DoCmds(i chan *string, n int, wg *util.SizedWaitGroup) {
	if 0 < len(option.Cmds) {
		start := option.Cmds[n]
		if DoCmdNode(start, i, wg) {
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
