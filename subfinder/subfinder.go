package subfinder

import (
	"context"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"os/user"
	"path/filepath"
)

type Writer struct {
	Out chan string
}

// 这里将获取到所有输出到domain信息
func (t *Writer) Write(p []byte) (n int, err error) {
	t.Out <- string(p)
	return
}

func DoSubfinder(a []string, out chan string) {
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
		Config:             filepath.Join(userHomeDir(), ".config/subfinder/config.yaml"),
		ProviderConfig:     filepath.Join(userHomeDir(), ".config/subfinder/provider-config.yaml"),
		JSON:               false,
		RateLimit:          0,
		ExcludeSources:     []string{},
		Resolvers:          []string{},
		Domain:             a,
		Sources:            []string{},
		DomainsFile:        ""}

	newRunner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
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
