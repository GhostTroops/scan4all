package main

import (
	"github.com/projectdiscovery/gologger"
	"github.com/veo/vscan/brute"
	httpxrunner "github.com/veo/vscan/pkg/httpx/runner"
	naaburunner "github.com/veo/vscan/pkg/naabu/runner"
	"github.com/veo/vscan/poc"
)

func main() {
	naabuoptions := naaburunner.ParseOptions()
	naabuRunner, err := naaburunner.NewRunner(naabuoptions)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	err = naabuRunner.RunEnumeration()
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}
	httpxoptions := httpxrunner.ParseOptions()
	httpxoptions.NoColor = naabuoptions.NoColor
	httpxoptions.Silent = naabuoptions.Silent
	httpxoptions.Output = naabuoptions.Output
	httpxoptions.HTTPProxy = naabuoptions.Proxy
	brute.HttpProxy = naabuoptions.Proxy
	poc.HttpProxy = naabuoptions.Proxy
	httpxoptions.Naabuinput = naaburunner.Naabuipports
	r, err := httpxrunner.New(httpxoptions)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	r.RunEnumeration()
	r.Close()
}
