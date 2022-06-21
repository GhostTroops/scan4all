package glog

import (
	"fmt"
	"log"
	"sync"
)

func init() {

}

var (
	logger *log.Logger
	level  LEVEL
	mu     sync.Mutex
)

type LEVEL int

const (
	DEBUG LEVEL = iota
	INFO
	WARN
	ERROR
	NONE
)

func SetLogger(l *log.Logger) {
	l.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	logger = l
}

func SetLevel(l LEVEL) {
	level = l
}

func checkLogger() {
	if logger == nil && level != NONE {
		panic("logger not inited")
	}
}

func Debug(v ...interface{}) {
	checkLogger()
	if level <= DEBUG {
		mu.Lock()
		defer mu.Unlock()
		logger.SetPrefix("[DEBUG]")
		logger.Output(2, fmt.Sprintln(v...))
	}
}
func Debugf(f string, v ...interface{}) {
	checkLogger()
	if level <= DEBUG {
		mu.Lock()
		defer mu.Unlock()
		logger.SetPrefix("[DEBUG]")
		logger.Output(2, fmt.Sprintln(fmt.Sprintf(f, v...)))
	}
}
func Info(v ...interface{}) {
	checkLogger()
	if level <= INFO {
		mu.Lock()
		defer mu.Unlock()
		logger.SetPrefix("[INFO]")
		logger.Output(2, fmt.Sprintln(v...))
	}
}
func Infof(f string, v ...interface{}) {
	checkLogger()
	if level <= INFO {
		mu.Lock()
		defer mu.Unlock()
		logger.SetPrefix("[INFO]")
		logger.Output(2, fmt.Sprintln(fmt.Sprintf(f, v...)))
	}
}
func Warn(v ...interface{}) {
	checkLogger()
	if level <= WARN {
		mu.Lock()
		defer mu.Unlock()
		logger.SetPrefix("[WARN]")
		logger.Output(2, fmt.Sprintln(v...))
	}
}

func Error(v ...interface{}) {
	checkLogger()
	if level <= ERROR {
		mu.Lock()
		defer mu.Unlock()
		logger.SetPrefix("[ERROR]")
		logger.Output(2, fmt.Sprintln(v...))
	}
}
func Errorf(f string, v ...interface{}) {
	checkLogger()
	if level <= ERROR {
		mu.Lock()
		defer mu.Unlock()
		logger.SetPrefix("[ERROR]")
		logger.Output(2, fmt.Sprintln(fmt.Sprintf(f, v...)))
	}
}
