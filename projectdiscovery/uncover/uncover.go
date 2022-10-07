package uncover

import (
	"context"
	"strings"

	// Attempts to increase the OS file descriptors - Fail silently
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/uncover/runner"
)

// https://github.com/projectdiscovery/uncover
/*
Query multiple search engine at once
Available Search engine support
Shodan
Censys
FOFA
Hunter
Quake
Zoomeye
*/
func DoUncover(targets []string) {
	// Parse the command line flags and read config files
	options := &runner.Options{Provider: &runner.Provider{},
		Query:   targets,
		Engine:  strings.Split("shodan,shodan-idb,fofa,censys", ","),
		Timeout: 30,
		Delay:   1,
		JSON:    true,
		Limit:   10000,
		NoColor: true,
		Silent:  true,
		Version: false,
		Verbose: false,
	}

	newRunner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}

	err = newRunner.Run(context.Background(), options.Query...)
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}
}
