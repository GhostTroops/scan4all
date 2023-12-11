package fuzz

import (
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"regexp"
	"strings"
)

var (
	Leaks = []*regexp.Regexp{
		regexp.MustCompile(`(<title>\s*Index of\s*[^<]*<\/title>)|(<a href="[^"]*">\s*Parent\s*Directory\s*<\/a>)`),
	}
)

func init() {
	util.RegInitFunc(func() {
		// 注册body中信息泄露的检测
		// 约定参数：body，url
		util.RegResponsCheckFunc(func(r *util.CheckerTools, i ...interface{}) {
			s := r.GetBodyStr(i...)
			var a []string
			for _, k := range Leaks {
				a1 := k.FindAllString(s, -1)
				if 0 < len(a1) {
					a = append(a, a1...)
				}
			}
			if 0 < len(a) {
				util.SendLog(fmt.Sprintf("%v", i), "leak", strings.Join(a, "\n"), "")
			}
		})
		//util.RegHeaderCheckFunc(func(r *util.CheckerTools, i ...interface{}) {
		//
		//})
	})
}
