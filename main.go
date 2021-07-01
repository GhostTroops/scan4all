package main

import (
	"github.com/projectdiscovery/gologger"
	naaburunner "github.com/projectdiscovery/naabu/v2/pkg/runner"
	httpxrunner "github.com/veo/vscan/pkg/httpx/runner"
)

func main() {
	naabuoptions := naaburunner.ParseOptions()
	naabuoptions.Output = "ips_port.txt"
	naabuRunner, err := naaburunner.NewRunner(naabuoptions)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}

	err = naabuRunner.RunEnumeration()
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}

	//httpx
	options := httpxrunner.ParseOptions()
	options.HTTPProxy = "http://127.0.0.1:8080"
	r, err := httpxrunner.New(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	r.RunEnumeration()
	r.Close()
}
