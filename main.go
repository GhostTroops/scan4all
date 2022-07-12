package main

import (
	"embed"
	"fmt"
	"github.com/hktalent/scan4all/pkg"
	naaburunner "github.com/hktalent/scan4all/pkg/naabu/v2/pkg/runner"
	"github.com/projectdiscovery/gologger"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"runtime"
)

//go:embed config/*
var config embed.FS

func init() {
	pkg.Init2(&config)
}

func main() {
	defer func() {
		log.Println("start close cache, StopCPUProfile... ")
		pkg.Cache1.Close()
		//if "true" == pkg.GetVal("autoRmCache") {
		//	os.RemoveAll(pkg.GetVal(pkg.CacheName))
		//}
	}()
	options := naaburunner.ParseOptions()
	if options.Debug {
		// debug 优化时启用///////////////////////
		go func() {
			fmt.Println("debug info: \nopen http://127.0.0.1:6060/debug/pprof/\n")
			http.ListenAndServe(":6060", nil)
		}()
		//////////////////////////////////////////*/
	}
	if false == options.Debug && false == options.Verbose {
		// disable standard logger (ref: https://github.com/golang/go/issues/19895)
		log.SetFlags(0)
		log.SetOutput(io.Discard)
	}
	pkg.G_Options = options
	if runtime.GOOS == "windows" {
		options.NoColor = true
	}
	naabuRunner, err := naaburunner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("naaburunner.NewRunner Could not create runner: %s\n", err)
	}
	gologger.Info().Msg("Port scan starting....")
	err = naabuRunner.RunEnumeration()
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}
	gologger.Info().Msg("Port scan over,web scan starting")
	err = naabuRunner.Httpxrun()
	if err != nil {
		gologger.Fatal().Msgf("naabuRunner.Httpxrun Could not run httpRunner: %s\n", err)
	}
}
