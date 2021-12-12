package main

import (
	"github.com/projectdiscovery/gologger"
	naaburunner "github.com/veo/vscan/pkg/naabu/runner"
	"runtime"
)

func main() {
	naabuoptions := naaburunner.ParseOptions()
	if runtime.GOOS == "windows" {
		naabuoptions.NoColor = true
	}
	naabuRunner, err := naaburunner.NewRunner(naabuoptions)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	err = naabuRunner.RunEnumeration()
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}
}
