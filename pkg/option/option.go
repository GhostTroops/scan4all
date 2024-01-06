package option

import (
	util "github.com/hktalent/go-utils"
	"log"
	"os/exec"
)

// 下一个节点的查询
type NextQuery struct {
	Default   string            `json:"default"`
	QueryPath map[string]string `json:"query_path"`
}

type Cmd struct {
	Proxy         int         `json:"proxy"`      // 使用的代理，默认不使用, 0 不使用
	RunServer     int         `json:"run_server"` // 在哪个server运行，默认不使用, 0 不使用
	X             int         `json:"x"`          // 执行顺序
	Name          string      `json:"name"`       // 不重复的key
	Cmd           string      `json:"cmd"`
	ResultRmKey   string      `json:"result_rm_key"`
	Next          []string    `json:"next"`
	SelfDo        string      `json:"self_do"`
	NextQueryPath *NextQuery  `json:"next_query_path"`
	Parms         interface{} // 传递下一层的时候附加的
}

var Cmds = []*Cmd{}

// 根据名字得到 命令节点
func GetCmdNode4key(k string) *Cmd {
	for _, x := range Cmds {
		if x.Name == k {
			return x
		}
	}
	return nil
}

func ParseConfig() {
	if o := util.GetAsAny("cmds"); nil != o {
		if data, err := util.Json.Marshal(o); nil == err {
			if err := util.Json.Unmarshal(data, &Cmds); nil != err {
				log.Println(err)
			} else {
				for _, x := range Cmds {
					if _, err := exec.LookPath(x.Name); nil != err {
						log.Println("can not found cmd: ", x.Name)
					}
				}
			}
		}
	}
}

func init() {
	util.RegInitFunc(ParseConfig)
}
