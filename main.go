package main

import (
	"github.com/projectdiscovery/gologger"
	httpxrunner "github.com/veo/vscan/pkg/httpx/runner"
	naaburunner "github.com/veo/vscan/pkg/naabu/runner"
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

	//httpx
	httpxoptions := httpxrunner.ParseOptions()
	httpxoptions.NoColor = naabuoptions.NoColor
	httpxoptions.Silent = naabuoptions.Silent
	//httpxoptions.HTTPProxy = "http://127.0.0.1:8080"
	//brute.HttpProxy = "http://127.0.0.1:8080"
	httpxoptions.Naabuinput = naaburunner.Naabuipports
	r, err := httpxrunner.New(httpxoptions)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	r.RunEnumeration()
	r.Close()
}
