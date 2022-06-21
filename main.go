package main

import (
	"github.com/hktalent/scan4all/pkg"
	naaburunner "github.com/hktalent/scan4all/pkg/naabu/v2/pkg/runner"
	"github.com/projectdiscovery/gologger"
	"runtime"
)

func main() {
	options := naaburunner.ParseOptions()
	pkg.G_Options = options
	if runtime.GOOS == "windows" {
		options.NoColor = true
	}
	naabuRunner, err := naaburunner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	err = naabuRunner.RunEnumeration()
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}
	gologger.Info().Msg("Port scan over,web scan starting")
	err = naabuRunner.Httpxrun()
	if err != nil {
		gologger.Fatal().Msgf("Could not run httpRunner: %s\n", err)
	}
}
