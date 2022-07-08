package main

import (
	"embed"
	"github.com/hktalent/scan4all/pkg"
	naaburunner "github.com/hktalent/scan4all/pkg/naabu/v2/pkg/runner"
	"github.com/projectdiscovery/gologger"
	"io"
	"log"
	"runtime"
	"sync"
)

//go:embed config/*
var config embed.FS

func init() {
	pkg.Init2(&config)
}

var Wg sync.WaitGroup

func main() {
	naaburunner.Wg = &Wg
	defer func() {
		pkg.Cache1.Close()
		//if "true" == pkg.GetVal("autoRmCache") {
		//	os.RemoveAll(pkg.GetVal(pkg.CacheName))
		//}
	}()
	options := naaburunner.ParseOptions()
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
	Wg.Wait()
}
