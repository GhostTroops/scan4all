package go_utils

import (
	"log"
	"runtime"
	"strings"
)

type RegFuncs struct {
	FuncList []func()
}

// 注册
func (r *RegFuncs) RegFunc(fn func()) {
	r.FuncList = append(r.FuncList, fn)
}

// tick 检测
var TickFunc = new(RegFuncs)
var ReleaseFunc = new(RegFuncs)

// 串行tick
func (r *RegFuncs) DoFunc() {
	for _, c := range r.FuncList {
		c()
	}
}

// Catch Panic
//
//	in your func: defer CatchPanic()
func CatchPanic() {
	if o := recover(); nil != o {
		log.Println(o)
	}
}

// 将该方法放到方法中运行，就可以打印出所有调用该方法的链路出来
func PrintCaller() {
	var i = 0
	for {
		i++
		if pc, file, line, ok := runtime.Caller(i); ok {
			fc := runtime.FuncForPC(pc)
			log.Printf("<-%s %s file:%s (line:%d)\n", strings.Repeat(":", i-1), fc.Name(), file, line) // , runtime.CallersFrames([]uintptr{pc})
			if "main.main" == fc.Name() {
				break
			}
		} else {
			break
		}
	}
}
