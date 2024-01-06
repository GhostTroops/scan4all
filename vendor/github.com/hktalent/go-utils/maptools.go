package go_utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
)

var rSplt = regexp.MustCompile(`[,; ]`)

func CloneObj[T any](i interface{}) *T {
	if data, err := Json.Marshal(i); nil == err {
		var m = new(T)
		if nil == Json.Unmarshal(data, &m) {
			return m
		}
	}
	return nil
}

// copy map
func copyMap(m map[string]string) map[string]string {
	m2 := reflect.MakeMap(reflect.TypeOf(m))
	for k, v := range m {
		m2.SetMapIndex(reflect.ValueOf(k), reflect.ValueOf(v))
	}
	return m2.Interface().(map[string]string)
}

// 移除不要的key
func RmMap(m *map[string]interface{}, a ...string) *map[string]interface{} {
	for _, x := range a {
		r := rSplt.Split(x, -1)
		for _, j := range r {
			if j = strings.TrimSpace(j); "" != j {
				delete(*m, j)
			}
		}
	}
	return m
}

// 多个对象合并
func MergeObjs(i ...interface{}) *map[string]interface{} {
	var m1 = map[string]interface{}{}
	for _, x := range i {
		if data, err := Json.Marshal(x); nil == err {
			Json.Unmarshal(data, &m1)
		}
	}
	return &m1
}

// 格式化 map 并返回 str
func Map2FormatStr(m *map[string]interface{}) string {
	var lk = GetLock("Map2FormatStr").Lock()
	defer lk.Unlock()
	if data, err := Json.Marshal(m); nil == err {
		var out bytes.Buffer
		if nil == json.Indent(&out, data, "", "\t") {
			return out.String()
		}
	}
	return ""
}

// 避免重复，并设置标记
func CheckNoRepeat4Onece(m *sync.Map, k interface{}) bool {
	if _, ok := m.Load(k); ok {
		return true
	}
	m.Store(k, true)
	return false
}

/*
移除空的、无效的值
*/
func RmNullMap(m *map[string]interface{}) *map[string]interface{} {
	if nil == m {
		return nil
	}
	var a []string
	for k, v := range *m {
		if m1, ok := v.(map[string]interface{}); ok {
			(*m)[k] = RmNullMap(&m1)
			continue
		}
		s1 := fmt.Sprintf("%v", v)
		if nil == v || s1 == "null" || "nil" == s1 || "" == s1 {
			a = append(a, k)
		}
	}
	for _, x := range a {
		delete(*m, x)
	}
	return m
}
