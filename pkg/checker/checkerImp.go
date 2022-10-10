package checker

import (
	"github.com/hktalent/ProScan4all/lib/util"
	"net/http"
	"strings"
)

const (
	RespHeader string = "RespHeader"
	RespBody   string = "RespBody"
	ReqHeader  string = "ReqHeader"
)

var (
	// ,RespJs,RespCss,RespTitle
	keys []string = strings.Split("RespHeader,RespBody,ReqHeader", ",")
)

// 检查器的设计：解耦、规范、统一，各类专注实现自己
//  1、允许未响应header、body、js、css等构建不同的检查器
//  2、每个检查器都有缓存
//  3、避免重复检查
//  4、具有自动释放缓存的机制，程序退出时自动消费（内存缓存）
type CheckerTools struct {
	Name      string                                `json:"name"`       // RespHeader,RespBody,RespJs,RespCss,RespTitle,ReqHeader
	checkFunc []func(*CheckerTools, ...interface{}) `json:"check_func"` // 注册的检查器
}

func GetInstance(name string) *CheckerTools {
	return util.GetObjFromNoRpt[*CheckerTools](name)
}

// 构建一个检查器
func New(name string) *CheckerTools {
	ct := util.GetObjFromNoRpt[*CheckerTools](name)
	if nil == ct {
		ct = &CheckerTools{Name: name}
		util.SetNoRpt(name, ct)
	}
	return ct
}

// 注册处理程序
func (r *CheckerTools) RegCheckFunc(fnChk ...func(*CheckerTools, ...interface{})) {
	r.checkFunc = append(r.checkFunc, fnChk...)
}

// 检查
func (r *CheckerTools) Check(parm ...interface{}) {
	for _, f := range r.checkFunc {
		f(r, parm...)
	}
}

// 获取一个header的值
func (r *CheckerTools) GetHead(p interface{}, key string) []string {
	if nil == p {
		return []string{}
	}
	if x1, ok := p.(map[string]string); ok {
		if x, ok := x1[key]; ok {
			return []string{x}
		}
	} else if x1, ok := p.(map[string][]string); ok {
		if x, ok := x1[key]; ok {
			return x
		}
	} else if x1, ok := p.(*http.Header); ok {
		if x := x1.Get(key); "" != x {
			return []string{x}
		}
	}
	return []string{}
}

// 头部检查，传入不同形态的头，函数根据需要处理
func CheckRespHeader(parm ...interface{}) {
	if x1 := GetInstance(keys[0]); nil != x1 {
		x1.Check(parm...)
	}
}

func init() {
	util.RegInitFunc(func() {
		for _, k := range keys {
			New(k)
		}
	})
}
