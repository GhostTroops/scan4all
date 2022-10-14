package util

import (
	"reflect"
	"strings"
)

// 判断s是否在数组a中
// 支持任何类型，支持泛型
func Contains[T any](a []T, s T) bool {
	for _, x := range a {
		if reflect.DeepEqual(s, x) {
			return true
		}
	}
	return false
}

// s中不能包含a中任何一个
func NotContains(s string, a []string) bool {
	for _, x := range a {
		if -1 == strings.Index(s, x) {
			continue
		} else {
			return false
		}
	}
	return true
}

var a1 = strings.Split("app,net,org,vip,cc,cn,co,io,com,gov.edu", ",")

// 兼容hacker one 域名表示方式,以下格式支持
// *.xxx.com
// *.xxx.xx1.*
func Convert2Domains(x string) []string {
	aRst := []string{}
	x = strings.TrimSpace(x)
	if "*.*" == x || -1 < strings.Index(x, ".*.") {
		return aRst
	}
	if -1 < strings.Index(x, "(*).") {
		x = x[4:]
	}
	if -1 < strings.Index(x, "*.") {
		x = x[2:]
	}
	if 2 > strings.Index(x, "*") {
		x = x[1:]
	}
	if -1 < strings.Index(x, ".*") {
		x = x[0 : len(x)-2]
		for _, j := range a1 {
			aRst = append(aRst, x+"."+j)
		}
	} else {
		aRst = append(aRst, x)
	}
	return aRst
}
