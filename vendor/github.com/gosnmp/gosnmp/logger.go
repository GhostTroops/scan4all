//go:build gosnmp_nodebug
// +build gosnmp_nodebug

// When building, specify the gosnmp_nodebug tag and logging will be completely disabled
// for example: go build -tags gosnmp_nodebug

package gosnmp

func (l *Logger) Print(v ...interface{}) {
}

func (l *Logger) Printf(format string, v ...interface{}) {
}
