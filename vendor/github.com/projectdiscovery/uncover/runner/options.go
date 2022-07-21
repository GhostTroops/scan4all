package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/folderutil"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
)

var (
	defaultConfigLocation         = filepath.Join(folderutil.HomeDirOrDefault("."), ".config/uncover/config.yaml")
	defaultProviderConfigLocation = filepath.Join(folderutil.HomeDirOrDefault("."), ".config/uncover/provider-config.yaml")
)

// Options contains the configuration options for tuning the enumeration process.
type Options struct {
	Query        goflags.FileStringSlice
	Engine       goflags.FileNormalizedStringSlice
	ConfigFile   string
	ProviderFile string
	OutputFile   string
	OutputFields string
	JSON         bool
	Raw          bool
	Limit        int
	Silent       bool
	Version      bool
	Verbose      bool
	NoColor      bool
	Timeout      int
	Delay        int
	delay        time.Duration
	Provider     *Provider
}

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{Provider: &Provider{}}
	var err error
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`quickly discover exposed assets on the internet using multiple search engines.`)

	flagSet.CreateGroup("input", "Input",
		flagSet.FileStringSliceVarP(&options.Query, "query", "q", []string{}, "search query, supports: stdin,file,config input (example: -q 'example query', -q 'query.txt')"),
		flagSet.FileNormalizedStringSliceVarP(&options.Engine, "engine", "e", []string{}, "search engine to query (shodan,shodan-idb,fofa,censys) (default shodan)"),
	)

	flagSet.CreateGroup("config", "Config",
		flagSet.StringVarP(&options.ProviderFile, "provider", "pc", defaultProviderConfigLocation, "provider configuration file"),
		flagSet.StringVar(&options.ConfigFile, "config", defaultConfigLocation, "flag configuration file"),
		flagSet.IntVar(&options.Timeout, "timeout", 30, "timeout in seconds"),
		flagSet.IntVar(&options.Delay, "delay", 1, "delay between requests in seconds (0 to disable)"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.OutputFile, "output", "o", "", "output file to write found results"),
		flagSet.StringVarP(&options.OutputFields, "field", "f", "ip:port", "field to display in output (ip,port,host)"),
		flagSet.BoolVarP(&options.JSON, "json", "j", false, "write output in JSONL(ines) format"),
		flagSet.BoolVarP(&options.Raw, "raw", "r", false, "write raw output as received by the remote api"),
		flagSet.IntVarP(&options.Limit, "limit", "l", 100, "limit the number of results to return"),
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "disable colors in output"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&options.Silent, "silent", false, "show only results in output"),
		flagSet.BoolVar(&options.Version, "version", false, "show version of the project"),
		flagSet.BoolVar(&options.Verbose, "v", false, "show verbose output"),
	)

	if err := flagSet.Parse(); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	options.configureOutput()

	showBanner()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", Version)
		os.Exit(0)
	}

	if options.ConfigFile != defaultConfigLocation {
		_ = options.loadConfigFrom(options.ConfigFile)
	}

	// create default provider file if it doesn't exist
	if !fileutil.FileExists(defaultProviderConfigLocation) {
		if err := fileutil.Marshal(fileutil.YAML, []byte(defaultProviderConfigLocation), Provider{}); err != nil {
			gologger.Warning().Msgf("couldn't write provider default file: %s\n", err)
		}
	}

	// provider chores
	_ = options.loadProvidersFrom(options.ProviderFile)
	if err = options.loadProvidersFromEnv(); err != nil {
		gologger.Warning().Msgf("couldn't parse env vars: %s\n", err)
	}

	if len(options.Engine) == 0 {
		options.Engine = append(options.Engine, "shodan")
		options.Engine = append(options.Engine, "shodan-idb")
	}

	// we make the assumption that input queries aren't that much
	if fileutil.HasStdin() {
		stdchan, err := fileutil.ReadFileWithReader(os.Stdin)
		if err != nil {
			gologger.Fatal().Msgf("couldn't read stdin: %s\n", err)
		}
		for query := range stdchan {
			options.Query = append(options.Query, query)
		}
	}

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	err = options.validateOptions()
	if err != nil {
		gologger.Fatal().Msgf("Program exiting: %s\n", err)
	}

	return options
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}

func (Options *Options) loadConfigFrom(location string) error {
	return fileutil.Unmarshal(fileutil.YAML, []byte(location), Options)
}

func (options *Options) loadProvidersFrom(location string) error {
	return fileutil.Unmarshal(fileutil.YAML, []byte(location), options.Provider)
}

func (options *Options) loadProvidersFromEnv() error {
	if key, exists := os.LookupEnv("SHODAN_API_KEY"); exists {
		options.Provider.Shodan = append(options.Provider.Shodan, key)
	}
	if id, exists := os.LookupEnv("CENSYS_API_ID"); exists {
		if secret, exists := os.LookupEnv("CENSYS_API_SECRET"); exists {
			options.Provider.Censys = append(options.Provider.Censys, fmt.Sprintf("%s:%s", id, secret))
		} else {
			return errors.New("missing censys secret")
		}
	}
	if email, exists := os.LookupEnv("FOFA_EMAIL"); exists {
		if key, exists := os.LookupEnv("FOFA_KEY"); exists {
			options.Provider.Fofa = append(options.Provider.Fofa, fmt.Sprintf("%s:%s", email, key))
		} else {
			return errors.New("missing fofa key")
		}
	}
	return nil
}

// validateOptions validates the configuration options passed
func (options *Options) validateOptions() error {
	// Check if domain, list of domains, or stdin info was provided.
	// If none was provided, then return.
	if len(options.Query) == 0 {
		return errors.New("no query provided")
	}

	// Both verbose and silent flags were used
	if options.Verbose && options.Silent {
		return errors.New("both verbose and silent mode specified")
	}

	// Validate threads and options
	if len(options.Engine) == 0 {
		return errors.New("no engine specified")
	}

	if options.Delay < 0 {
		return errors.New("delay can't be negative")
	} else {
		options.delay = time.Duration(options.Delay) * time.Second
	}

	return nil
}

func (options *Options) hasAnyAnonymousProvider() bool {
	for _, engine := range options.Engine {
		if strings.EqualFold(engine, "shodan-idb") {
			return true
		}
	}
	return false
}
