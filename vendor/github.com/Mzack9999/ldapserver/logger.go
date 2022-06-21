package ldapserver

import (
	"io/ioutil"
	"log"
	"os"
)

var Logger logger

// Logger represents log.Logger functions from the standard library
type logger interface {
	Fatal(v ...interface{})
	Fatalf(format string, v ...interface{})
	Fatalln(v ...interface{})

	Panic(v ...interface{})
	Panicf(format string, v ...interface{})
	Panicln(v ...interface{})

	Print(v ...interface{})
	Printf(format string, v ...interface{})
	Println(v ...interface{})
}

func init() {
	Logger = log.New(os.Stdout, "", log.LstdFlags)
}

var (
	// DiscardingLogger can be used to disable logging output
	DiscardingLogger = log.New(ioutil.Discard, "", 0)
)
