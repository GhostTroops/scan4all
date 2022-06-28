package subfinder

import (
	"context"
	"errors"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"io"
	"os"
	"os/user"
	"path/filepath"
)

var (
	defaultConfigLocation         = filepath.Join(userHomeDir(), ".config/subfinder/config.yaml")
	defaultProviderConfigLocation = filepath.Join(userHomeDir(), ".config/subfinder/provider-config.yaml")
)

type Writer struct {
	Out chan string
}

// 这里将获取到所有输出到domain信息
func (t *Writer) Write(p []byte) (n int, err error) {
	t.Out <- string(p)
	return
}

// loadProvidersFrom runs the app with source config
func loadProvidersFrom(location string, options *runner.Options) {
	if len(options.AllSources) == 0 {
		options.AllSources = passive.DefaultAllSources
	}
	if len(options.Recursive) == 0 {
		options.Recursive = passive.DefaultRecursiveSources
	}
	// todo: move elsewhere
	if len(options.Resolvers) == 0 {
		options.Recursive = resolve.DefaultResolvers
	}
	if len(options.Sources) == 0 {
		options.Sources = passive.DefaultSources
	}

	options.Providers = &runner.Providers{}
	// We skip bailing out if file doesn't exist because we'll create it
	// at the end of options parsing from default via goflags.
	if err := options.Providers.UnmarshalFrom(location); isFatalErr(err) && !errors.Is(err, os.ErrNotExist) {
		gologger.Fatal().Msgf("Could not read providers from %s: %s\n", location, err)
	}
}

func DoSubfinder(a []string, out chan string, done chan bool) {
	defer func() {
		done <- true
		close(done)
	}()
	// Parse the command line flags and read config files
	options := &runner.Options{
		Verbose:            false,
		NoColor:            false,
		Silent:             true,
		RemoveWildcard:     true,
		All:                false,
		OnlyRecursive:      false,
		Threads:            32,
		Timeout:            30,
		MaxEnumerationTime: 10,
		Output:             &Writer{Out: out}, // 需要包装
		OutputFile:         "",
		OutputDirectory:    "",
		ResolverList:       "",
		Proxy:              "",
		Version:            false,
		ExcludeIps:         false,
		CaptureSources:     false,
		HostIP:             false,
		Config:             defaultConfigLocation,
		ProviderConfig:     defaultProviderConfigLocation,
		JSON:               false,
		RateLimit:          0,
		ExcludeSources:     []string{},
		Resolvers:          []string{},
		Domain:             a,
		Sources:            []string{},
		DomainsFile:        ""}
	if fileutil.FileExists(options.ProviderConfig) {
		gologger.Info().Msgf("Loading provider config file %s", options.ProviderConfig)
		loadProvidersFrom(options.ProviderConfig, options)
	} else {
		gologger.Info().Msg("Loading the default")
		loadProvidersFrom(defaultProviderConfigLocation, options)
	}
	newRunner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("newRunner, err := runner.NewRunner Could not create runner: %s\n", err)
	}

	err = newRunner.RunEnumeration(context.Background())
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}
}
func userHomeDir() string {
	usr, err := user.Current()
	if err != nil {
		gologger.Fatal().Msgf("Could not get user home directory: %s\n", err)
	}
	return usr.HomeDir
}

func isFatalErr(err error) bool {
	return err != nil && !errors.Is(err, io.EOF)
}
