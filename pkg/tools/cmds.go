package tools

import (
	"fmt"
	"github.com/GhostTroops/scan4all/pkg/common"
	"github.com/GhostTroops/scan4all/pkg/option"
	. "github.com/GhostTroops/scan4all/pkg/utils"
	util "github.com/hktalent/go-utils"
	"io"
	"log"
	"os"
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
func NoRepeat(i chan *string, key string, wg *util.SizedWaitGroup, isNext bool) chan *string {
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
		var x *string
		defer func() {
			err := recover()
			if nil != err {
				log.Println(key, err, x)
				if nil != x && "" != *x {
					out = make(chan *string)
					DoCmd4Key(key, out, wg, isNext)
					out <- x
					close(out)
				}
			}
		}()
		for x = range i {
			if *x = strings.TrimSpace(*x); "" == *x || util.TestRepeat(*x, key) {
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
		if isNext {
			close(out)
		}
	})
	return out
}

// 为异常的情况，重启开启命令
func DoCmd4Key(key string, iptTmp1 chan *string, wg *util.SizedWaitGroup, isNext bool) {
	if cNode := option.GetCmdNode4key(key); nil != cNode {
		common.RegCmd(cNode.Cmd, nil)
		DoNodeCmd(cNode, iptTmp1, wg, isNext)
	}
}

// 异步执行
func DoNodeCmd(cNode1 *option.Cmd, iptTmp1 chan *string, wg *util.SizedWaitGroup, isNext bool) {
	util.WaitFunc4Wg(wg, func() {
		DoCmdNode(cNode1, iptTmp1, wg, isNext)
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
					DoNodeCmd(cNode, iptTmp, wg, true)
					//common.ChanEngine.SendData(DoCmdChanIptChan, &DoCmdChan{Cmd: cNode, Input: iptTmp, Wg: wg}, wg)
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
func DoCmdNode(cmd1 *option.Cmd, i2 chan *string, wg *util.SizedWaitGroup, isNext bool) bool {
	bRst := false
	i1 := NoRepeat(i2, cmd1.Name, wg, isNext)
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
						DoAorS(util.GetJQ(m, x), i2, TrimXx, cmd1.Name)
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
				// 这里不能给 DoCmdChanIpt 发，后缀会导致 回调无法结束
				//DoNext(cmd1, &m, wg)
				common.ChanEngine.SendData(DoCmdChanIptChan, &DoCmdChan{Cmd: cmd1, Input: nil, NextData: &m, Wg: wg}, wg)
			}
		}, i1, wg)
		bRst = true
		break
	case Nmap, Masscan:
		DoIOCmd(cmd1, i1, wg)
	case Gopoc:
	case Filefuzz:

	}
	return bRst
}

/*
	ip 与 domain 的多对多关系

1、domain 转 ip，同时保留映射关系，到下一层命令前切换回 domain
2、检查是否执行过，执行过就直接使用结果，压入结果
3、这里必须关闭out ，后缀后面读取到临时危机就回卡住
*/
func GetDomain2Ip(i2 chan *string, aRst *[]*map[string]interface{}, szTag string) (chan *string, map[string][]string) {
	var out = make(chan *string)
	var m = map[string][]string{}
	go func() {
		defer close(out)
		var doIp09 = func(szIp string) {
			if !util.TestRepeat(szIp + "_doIp09_GetDomain2Ip") {
				if a := common.QueryRmtDbBBSec(fmt.Sprintf(`%stags:%s %sip:"%s"`, common.AddStr, szTag, common.AddStr, szIp), 5000); nil != a && 0 < len(a) {
					for _, x := range a {
						if sI, ok := (*x)["ip"]; ok && sI == szIp {
							*aRst = append(*aRst, x)
						}
					}
				} else {
					out <- &szIp
				}
			}
		}
		for s := range i2 {
			if nil != s {
				if util.IsIp(*s) {
					m[*s] = util.RemoveDuplication_mapNoEmpy(append(m[*s], *s))
					doIp09(*s)
				} else {
					if a := util.GetIps(*s); nil != a && 0 < len(a) {
						for _, y := range a {
							m[y] = util.RemoveDuplication_mapNoEmpy(append(m[y], *s))
							doIp09(y)
						}
					}
				}
			}
		}
		//close(i2)
	}()
	return out, m
}

// 输入、输出  临时文件名 命令
func DoIOCmd(cmd1 *option.Cmd, i2 chan *string, wg *util.SizedWaitGroup) {
	util.WaitFunc4Wg(wg, func() {
		var aRst []*map[string]interface{}

		i3, mIps := GetDomain2Ip(i2, &aRst, cmd1.Name)
		out := common.GetOutTmpFile("xml")
		in := common.GetTmpFile(i3, "txt")
		if data, err := os.ReadFile(in); nil != err || nil == data || 0 == len(data) {
			os.Remove(in)
			return
		}
		var szCmd = cmd1.Cmd
		if Nmap == cmd1.Name && nil != cmd1.Parms {
			var aPort = cmd1.Parms.(*[]string)
			if nil == aPort || 0 == len(*aPort) {
				return
			}
			szCmd = fmt.Sprintf(szCmd, in, out, strings.Join(*aPort, ","))
		} else {
			szCmd = fmt.Sprintf(szCmd, in, out)
		}
		cmd := common.NewAsCmd(wg, func(wt io.WriteCloser) {
			wt.Close()
		})

		cmd.DoCmdOutLine4Cbk(func(s *string) {
			if nil == s { // nil 结束了，就开始读取结果文件
				if Nmap == cmd1.Name {
					common.ParseNmapXml(func(mRst *map[string]interface{}) {
						if nil == mRst || 0 == len(*mRst) {
							return
						}
						mT1 := *mRst
						mT1["tags"] = cmd1.Name
						if oPort, ok := mT1["port"]; ok {
							if mPort, ok := oPort.(map[string]interface{}); ok && nil != mPort {
								if oPort1, ok := mPort["port"]; ok && nil != oPort1 {
									if aD := mIps[mT1["ip"].(string)]; nil != aD && 0 < len(aD) {
										for _, szDomain := range aD {
											mT1["domain"] = szDomain
											mT1["id"] = util.GetSha1(s, szDomain, cmd1.Name, mT1["ip"].(string), oPort1.(string))
											common.Save2RmtDb(mT1, cmd1.Name, ".id")
										}
									}
								}
							}
						}
					}, out)
				} else if Masscan == cmd1.Name {
					var aPort []string
					var aDomain []string
					common.ParseMasscanXmlCbk(func(s string, s2 string) {
						aPort = append(aPort, s2)
						// 保存 扫描 结果
						if aD := mIps[s]; nil != aD && 0 < len(aD) {
							for _, szDomain := range aD {
								aDomain = append(aDomain, szDomain)
								var mT1 = map[string]interface{}{"tags": cmd1.Name, "ip": s, "domain": szDomain, "iport": fmt.Sprintf("%s:%s", szDomain, s2)}
								aRst = append(aRst, &mT1)
								mT1["id"] = util.GetSha1(s, szDomain, cmd1.Name, s2)
								common.Save2RmtDb(mT1, cmd1.Name, ".id")
								log.Printf(`{"ip":"%s","domain":"%s","port":%s}`+"\n", s, szDomain, s2)
							}
						}
					}, out)
					if nil != aPort && 0 < len(aPort) {
						aPort = util.RemoveDuplication_mapNoEmpy(aPort)
						aDomain = util.RemoveDuplication_mapNoEmpy(aDomain)
						var nextInput = map[string]interface{}{"target": aDomain, "ports": aPort}
						// do next
						cmd2 := util.CloneObj[option.Cmd](cmd1)
						cmd2.Parms = &aPort
						common.ChanEngine.SendData(DoCmdChanIptChan, &DoCmdChan{Cmd: cmd2, Input: nil, NextData: &nextInput, Wg: wg}, wg)

					}
				}
			}
		}, szCmd)

	})
}

/*
"masscan": "nmap","httpx","tlsx"
*/

type DoCmdChan struct {
	Cmd      *option.Cmd
	Input    chan *string
	NextData *map[string]interface{}
	Wg       *util.SizedWaitGroup
}

func DoOneCmdChan(cmd *DoCmdChan, wg *util.SizedWaitGroup) {
	util.WaitFunc4Wg(wg, func() {
		if nil != cmd {
			if nil == cmd.NextData && cmd.Input != nil {
				DoNodeCmd(cmd.Cmd, cmd.Input, wg, false)
				//DoCmdNode(cmd.Cmd, cmd.Input, wg)
			} else if nil != cmd.NextData {
				DoNext(cmd.Cmd, cmd.NextData, wg)
			}
		}
	})
}

const DoCmdChanIptChan = "DoCmdChanIpt"

func DoCmds(i chan *string, n int, wg *util.SizedWaitGroup) {
	if 0 < len(option.Cmds) {
		start := option.Cmds[n]
		common.ChanEngine.SetWg(wg)
		common.ChanEngine.SendData(DoCmdChanIptChan, &DoCmdChan{Cmd: start, Input: i, Wg: wg}, wg)
	}
}

func init() {
	util.RegInitFunc(func() {
		common.ChanEngine.RegisterHandler(DoCmdChanIptChan, func(i interface{}) {
			if cmd, ok := i.(*DoCmdChan); ok && nil != cmd {
				DoOneCmdChan(cmd, cmd.Wg)
			}
		})
	})
}
