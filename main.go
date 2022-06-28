package main

import (
	"github.com/hktalent/scan4all/pkg"
	"github.com/hktalent/scan4all/pkg/hydra"
	naaburunner "github.com/hktalent/scan4all/pkg/naabu/v2/pkg/runner"
	"github.com/projectdiscovery/gologger"
	"os"
	"runtime"
)

func main() {
	defer func() {
		pkg.Cache1.Close()
		if "true" == pkg.GetVal("autoRmCache") {
			os.RemoveAll(pkg.GetVal(pkg.CacheName))
		}
	}()
	options := naaburunner.ParseOptions()
	pkg.G_Options = options
	if runtime.GOOS == "windows" {
		options.NoColor = true
	}
	naabuRunner, err := naaburunner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("naaburunner.NewRunner Could not create runner: %s\n", err)
	}
	err = naabuRunner.RunEnumeration()
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}
	gologger.Info().Msg("Port scan over,web scan starting")
	// 弱密码检测
	hydra.DoNmapRst()
	err = naabuRunner.Httpxrun()
	if err != nil {
		gologger.Fatal().Msgf("naabuRunner.Httpxrun Could not run httpRunner: %s\n", err)
	}
}
