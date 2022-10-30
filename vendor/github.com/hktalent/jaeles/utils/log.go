package utils

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/hktalent/jaeles/libs"
	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

var logger = logrus.New()

// InitLog init log
func InitLog(options *libs.Options) {
	logger = &logrus.Logger{
		Out:   os.Stdout,
		Level: logrus.InfoLevel,
		Formatter: &prefixed.TextFormatter{
			ForceColors:     true,
			ForceFormatting: true,
		},
	}

	if options.LogFile != "" {
		options.LogFile = NormalizePath(options.LogFile)
		dir := path.Dir(options.LogFile)
		tmpFile, _ := ioutil.TempFile(dir, "jaeles-*.log")
		options.LogFile = tmpFile.Name()
		dir = filepath.Dir(options.LogFile)
		if !FolderExists(dir) {
			os.MkdirAll(dir, 0755)
		}
		f, err := os.OpenFile(options.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			logger.Errorf("error opening file: %v", err)
		}

		mwr := io.MultiWriter(os.Stdout, f)
		logger = &logrus.Logger{
			Out:   mwr,
			Level: logrus.InfoLevel,
			Formatter: &prefixed.TextFormatter{
				ForceColors:     true,
				ForceFormatting: true,
			},
		}
	}

	if options.Debug == true {
		logger.SetLevel(logrus.DebugLevel)
	} else if options.Verbose == true {
		logger.SetOutput(os.Stdout)
		logger.SetLevel(logrus.InfoLevel)
	} else {
		logger.SetLevel(logrus.PanicLevel)
		logger.SetOutput(ioutil.Discard)
	}
	if options.LogFile != "" {
		logger.Info(fmt.Sprintf("Store log file to: %v", options.LogFile))
	}
}

// PrintLine print seperate line
func PrintLine() {
	dash := color.HiWhiteString("-")
	fmt.Println(strings.Repeat(dash, 40))
}

// GoodF print good message
func GoodF(format string, args ...interface{}) {
	good := color.HiGreenString("[+]")
	fmt.Fprintf(os.Stderr, "%s %s\n", good, fmt.Sprintf(format, args...))
}

// BannerF print info message
func BannerF(format string, data string) {
	banner := fmt.Sprintf("%v%v%v ", color.WhiteString("["), color.BlueString(format), color.WhiteString("]"))
	fmt.Printf("%v%v\n", banner, color.HiGreenString(data))
}

// BlockF print info message
func BlockF(name string, data string) {
	banner := fmt.Sprintf("%v%v%v ", color.WhiteString("["), color.GreenString(name), color.WhiteString("]"))
	fmt.Printf(fmt.Sprintf("%v%v\n", banner, data))
}

// InforF print info message
func InforF(format string, args ...interface{}) {
	logger.Info(fmt.Sprintf(format, args...))
}

// ErrorF print good message
func ErrorF(format string, args ...interface{}) {
	logger.Error(fmt.Sprintf(format, args...))
}

// WarningF print good message
func WarningF(format string, args ...interface{}) {
	good := color.YellowString("[!]")
	fmt.Fprintf(os.Stderr, "%s %s\n", good, fmt.Sprintf(format, args...))
}

// DebugF print debug message
func DebugF(format string, args ...interface{}) {
	logger.Debug(fmt.Sprintf(format, args...))
}
