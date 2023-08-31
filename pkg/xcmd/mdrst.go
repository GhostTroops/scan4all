package xcmd

import (
	"fmt"
	"github.com/hktalent/gson"
	"github.com/hktalent/scan4all/lib/util"
	jsoniter "github.com/json-iterator/go"
	"strings"
	"time"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

// 将数据a转换未数组对象
func GetMore(a []string, t string, a1 []string, getId func(*map[string]interface{}) string) []interface{} {
	var aR []interface{}
	szCmd := strings.Join(a1, " ")
	for _, x := range a {
		obj := gson.NewFrom(x)
		obj.Del("timestamp")
		switch t {
		//case uncover:
		//
		default:
			if m, ok := obj.Val().(map[string]interface{}); ok {
				m["type"] = t
				m["cmd"] = szCmd
				m["date"] = time.Now()
				m["id"] = getId(&m)
				aR = append(aR, m)
			}
		}
	}
	return aR
}

// 一次发送多个对象
func SaveMdRst(s, t string, a1 []string) {
	a := strings.Split(strings.TrimSpace(s), "\n")
	switch t {
	case tlsx:
		if oR := GetMore(a, t, a1, func(m1 *map[string]interface{}) string {
			m := *m1
			return fmt.Sprintf("%s_%s_%v", m["type"], m["host"], m["port"])
		}); nil != oR && 0 < len(oR) {
			util.SendReq(oR, "xxx", t)
		}
	// +type:uncover +cmd:"China Lodging Group"
	case uncover:
		if oR := GetMore(a, t, a1, func(m1 *map[string]interface{}) string {
			m := *m1
			return fmt.Sprintf("%s_%s_%v", m["type"], m["ip"], m["port"])
		}); nil != oR && 0 < len(oR) {
			util.SendReq(oR, "xxx", t)
		}
	case shuffledns: // massdns
		if oR := GetMore(a, t, a1, func(m1 *map[string]interface{}) string {
			m := *m1
			return fmt.Sprintf("%s_%s", m["type"], m["hostname"])
		}); nil != oR && 0 < len(oR) {
			util.SendReq(oR, "xxx", t)
		}
	}

}
