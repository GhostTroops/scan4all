package slog

import (
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/GhostTroops/scan4all/pkg/kscan/lib/color"
	"github.com/lcvvvv/gonmap/lib/chinese"
	"io"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"strings"
)

var splitStr = "> "

type Level int

type Logger interface {
	Println(...interface{})
	Printf(string, ...interface{})
}

type logger struct {
	log      *log.Logger
	modifier func(string) string
	filter   func(string) bool
}

func (l *logger) Printf(format string, s ...interface{}) {
	expr := fmt.Sprintf(format, s...)
	l.Println(expr)
}

func (l *logger) Println(s ...interface{}) {
	expr := fmt.Sprint(s...)
	if l.modifier != nil {
		expr = l.modifier(expr)
	}
	if l.filter != nil {
		if l.filter(expr) == true {
			return
		}
	}
	l.log.Println(expr)
}

var info = Logger(&logger{
	log.New(os.Stdout, "\r[+]", log.Ldate|log.Ltime),
	color.Green,
	nil,
})
var warn = Logger(&logger{
	log.New(os.Stdout, "\r[*]", log.Ldate|log.Ltime),
	color.Red,
	nil,
})
var err = Logger(&logger{
	log.New(io.MultiWriter(os.Stderr), "\rError:", 0),
	nil,
	nil,
})
var dbg = Logger(&logger{
	log.New(os.Stdout, "\r[-]", log.Ldate|log.Ltime),
	debugModifier,
	debugFilter,
})
var data = Logger(log.New(os.Stdout, "\r", 0))

func SetEncoding(v string) {
	encoding = v
}

var encoding = "utf-8"

const (
	DEBUG Level = 0x0000a1
	INFO        = 0x0000b2
	WARN        = 0x0000c3
	ERROR       = 0x0000d4
	DATA        = 0x0000f5
	NONE        = 0x0000e6
)

func Printf(level Level, format string, s ...interface{}) {
	Println(level, fmt.Sprintf(format, s...))
}

func Println(level Level, s ...interface{}) {
	logStr := fmt.Sprint(s...)
	if encoding == "gb2312" {
		logStr = chinese.ToGBK(logStr)
	} else {
		logStr = chinese.ToUTF8(logStr)
	}

	switch level {
	case DEBUG:
		dbg.Println(logStr)
	case INFO:
		info.Println(logStr)
	case WARN:
		warn.Println(logStr)
	case ERROR:
		err.Println(logStr)
		os.Exit(0)
	case DATA:
		data.Println(logStr)
	default:
		return
	}
}

func Debug() Logger {
	return dbg
}

func SetLogger(level Level) {
	if level > ERROR {
		err = Logger(log.New(ioutil.Discard, "", 0))
	}
	if level > WARN {
		warn = Logger(log.New(ioutil.Discard, "", 0))
	}
	if level > INFO {
		info = Logger(log.New(ioutil.Discard, "", 0))
	}
	if level > DEBUG {
		dbg = Logger(&logger{
			log.New(ioutil.Discard, "\r[-]", log.Ldate|log.Ltime),
			debugModifier,
			debugFilter,
		})
	}

	if level > NONE {
		//nothing
	}
}

func debugModifier(s string) string {
	_, file, line, _ := runtime.Caller(3)
	file = file[strings.LastIndex(file, "/")+1:]
	logStr := fmt.Sprintf("%s%s(%d) %s", splitStr, file, line, s)
	logStr = color.Yellow(logStr)
	return logStr
}

func debugFilter(s string) bool {
	//Debug 过滤器
	if util.StrContains(s, "too many open") { //发现存在线程过高错误
		fmt.Println("当前线程过高，请降低线程!或者请执行\"ulimit -n 50000\"命令放开操作系统限制")
		os.Exit(0)
	}
	//if strings.Contains(s, "STEP1:CONNECT") {
	//	return true
	//}
	return false
}
