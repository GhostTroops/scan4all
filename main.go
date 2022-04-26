package main

import (
	"github.com/projectdiscovery/gologger"
	naaburunner "github.com/veo/vscan/pkg/naabu/v2/pkg/runner"
)

func main() {
	options := naaburunner.ParseOptions()
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
