package dnsxx

import (
	"errors"
	"math"
	"strconv"
	"strings"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/goconfig"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

const (
	DefaultResumeFile = "resume.cfg"
)

type ResumeCfg struct {
	ResumeFrom   string
	Index        int
	current      string
	currentIndex int
}

type Options struct {
	Resolvers         string
	Hosts             string
	Domains           string
	WordList          string
	Threads           int
	RateLimit         int
	Retries           int
	OutputFormat      string
	OutputFile        string
	Raw               bool
	Silent            bool
	Verbose           bool
	Version           bool
	Response          bool
	ResponseOnly      bool
	A                 bool
	AAAA              bool
	NS                bool
	CNAME             bool
	PTR               bool
	MX                bool
	SOA               bool
	TXT               bool
	AXFR              bool
	JSON              bool
	Trace             bool
	TraceMaxRecursion int
	WildcardThreshold int
	WildcardDomain    string
	ShowStatistics    bool
	rcodes            map[int]struct{}
	RCode             string
	hasRCodes         bool
	Resume            bool
	resumeCfg         *ResumeCfg
	HostsFile         bool
	Stream            bool
	CAA               bool
	OutputCDN         bool
	HealthCheck       bool
}

// ShouldLoadResume resume file
func (options *Options) ShouldLoadResume() bool {
	return options.Resume && fileutil.FileExists(DefaultResumeFile)
}

// ShouldSaveResume file
func (options *Options) ShouldSaveResume() bool {
	return true
}

// ParseOptions parses the command line options for application
func ParseOptions(args ...string) *Options {
	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`dnsx is a fast and multi-purpose DNS toolkit allow to run multiple probes using retryabledns library.`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringVarP(&options.Hosts, "list", "l", "", "list of sub(domains)/hosts to resolve (file or stdin)"),
		flagSet.StringVarP(&options.Domains, "domain", "d", "", "list of domain to bruteforce (file or comma separated or stdin)"),
		flagSet.StringVarP(&options.WordList, "wordlist", "w", "", "list of words to bruteforce (file or comma separated or stdin)"),
	)

	flagSet.CreateGroup("query", "Query",
		flagSet.BoolVar(&options.A, "a", false, "query A record (default)"),
		flagSet.BoolVar(&options.AAAA, "aaaa", false, "query AAAA record"),
		flagSet.BoolVar(&options.CNAME, "cname", false, "query CNAME record"),
		flagSet.BoolVar(&options.NS, "ns", false, "query NS record"),
		flagSet.BoolVar(&options.TXT, "txt", false, "query TXT record"),
		flagSet.BoolVar(&options.PTR, "ptr", false, "query PTR record"),
		flagSet.BoolVar(&options.MX, "mx", false, "query MX record"),
		flagSet.BoolVar(&options.SOA, "soa", false, "query SOA record"),
		flagSet.BoolVar(&options.AXFR, "axfr", false, "query AXFR"),
		flagSet.BoolVar(&options.CAA, "caa", false, "query CAA record"),
	)

	flagSet.CreateGroup("filter", "Filter",
		flagSet.BoolVarP(&options.Response, "resp", "re", false, "display dns response"),
		flagSet.BoolVarP(&options.ResponseOnly, "resp-only", "ro", false, "display dns response only"),
		flagSet.StringVarP(&options.RCode, "rcode", "rc", "", "filter result by dns status code (eg. -rcode noerror,servfail,refused)"),
	)

	flagSet.CreateGroup("probe", "Probe",
		flagSet.BoolVar(&options.OutputCDN, "cdn", false, "display cdn name"),
	)

	flagSet.CreateGroup("rate-limit", "Rate-limit",
		flagSet.IntVarP(&options.Threads, "threads", "t", 100, "number of concurrent threads to use"),
		flagSet.IntVarP(&options.RateLimit, "rate-limit", "rl", -1, "number of dns request/second to make (disabled as default)"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.OutputFile, "output", "o", "", "file to write output"),
		flagSet.BoolVar(&options.JSON, "json", false, "write output in JSONL(ines) format"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVarP(&options.HealthCheck, "health-check", "hc", false, "run diagnostic check up"),
		flagSet.BoolVar(&options.Silent, "silent", false, "display only results in the output"),
		flagSet.BoolVarP(&options.Verbose, "verbose", "v", false, "display verbose output"),
		flagSet.BoolVarP(&options.Raw, "debug", "raw", false, "display raw dns response"),
		flagSet.BoolVar(&options.ShowStatistics, "stats", false, "display stats of the running scan"),
		flagSet.BoolVar(&options.Version, "version", false, "display version of dnsx"),
	)

	flagSet.CreateGroup("optimization", "Optimization",
		flagSet.IntVar(&options.Retries, "retry", 2, "number of dns attempts to make (must be at least 1)"),
		flagSet.BoolVarP(&options.HostsFile, "hostsfile", "hf", false, "use system host file"),
		flagSet.BoolVar(&options.Trace, "trace", false, "perform dns tracing"),
		flagSet.IntVar(&options.TraceMaxRecursion, "trace-max-recursion", math.MaxInt16, "Max recursion for dns trace"),
		flagSet.BoolVar(&options.Resume, "resume", false, "resume existing scan"),
		flagSet.BoolVar(&options.Stream, "stream", false, "stream mode (wordlist, wildcard, stats and stop/resume will be disabled)"),
	)

	flagSet.CreateGroup("configs", "Configurations",
		flagSet.StringVarP(&options.Resolvers, "resolver", "r", "", "list of resolvers to use (file or comma separated)"),
		flagSet.IntVarP(&options.WildcardThreshold, "wildcard-threshold", "wt", 5, "wildcard filter threshold"),
		flagSet.StringVarP(&options.WildcardDomain, "wildcard-domain", "wd", "", "domain name for wildcard filtering (other flags will be ignored)"),
	)

	_ = flagSet.CommandLine.Parse(args)

	// Read the inputs and configure the logging
	options.configureOutput()

	err := options.configureRcodes()
	if err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	err = options.configureResume()
	if err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	options.validateOptions()

	return options
}

func (options *Options) validateOptions() {
	if options.Response && options.ResponseOnly {
		gologger.Fatal().Msgf("resp and resp-only can't be used at the same time")
	}

	if options.Retries == 0 {
		gologger.Fatal().Msgf("retries must be at least 1")
	}

	wordListPresent := options.WordList != ""
	domainsPresent := options.Domains != ""
	hostsPresent := options.Hosts != ""

	if hostsPresent && (wordListPresent || domainsPresent) {
		gologger.Fatal().Msgf("list(l) flag can not be used domain(d) or wordlist(w) flag")
	}

	if wordListPresent && !domainsPresent {
		gologger.Fatal().Msg("missing domain(d) flag required with wordlist(w) input")
	}
	if domainsPresent && !wordListPresent {
		gologger.Fatal().Msgf("missing wordlist(w) flag required with domain(d) input")
	}

	// stdin can be set only on one flag
	if argumentHasStdin(options.Domains) && argumentHasStdin(options.WordList) {
		if options.Stream {
			gologger.Fatal().Msgf("argument stdin not supported in stream mode")
		}
		gologger.Fatal().Msgf("stdin can be set for one flag")
	}

	if options.Stream {
		if wordListPresent {
			gologger.Fatal().Msgf("wordlist not supported in stream mode")
		}
		if domainsPresent {
			gologger.Fatal().Msgf("domains not supported in stream mode")
		}
		if options.Resume {
			gologger.Fatal().Msgf("resume not supported in stream mode")
		}
		if options.WildcardDomain != "" {
			gologger.Fatal().Msgf("wildcard not supported in stream mode")
		}
		if options.ShowStatistics {
			gologger.Fatal().Msgf("stats not supported in stream mode")
		}
	}
}

func argumentHasStdin(arg string) bool {
	return arg == stdinMarker
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}

func (options *Options) configureRcodes() error {
	options.rcodes = make(map[int]struct{})
	rcodes := strings.Split(options.RCode, ",")
	for _, rcode := range rcodes {
		var rc int
		switch strings.ToLower(rcode) {
		case "":
			continue
		case "noerror":
			rc = 0
		case "formerr":
			rc = 1
		case "servfail":
			rc = 2
		case "nxdomain":
			rc = 3
		case "notimp":
			rc = 4
		case "refused":
			rc = 5
		case "yxdomain":
			rc = 6
		case "yxrrset":
			rc = 7
		case "nxrrset":
			rc = 8
		case "notauth":
			rc = 9
		case "notzone":
			rc = 10
		case "badsig", "badvers":
			rc = 16
		case "badkey":
			rc = 17
		case "badtime":
			rc = 18
		case "badmode":
			rc = 19
		case "badname":
			rc = 20
		case "badalg":
			rc = 21
		case "badtrunc":
			rc = 22
		case "badcookie":
			rc = 23
		default:
			var err error
			rc, err = strconv.Atoi(rcode)
			if err != nil {
				return errors.New("invalid rcode value")
			}
		}

		options.rcodes[rc] = struct{}{}
	}

	options.hasRCodes = options.RCode != ""

	// Set rcode to 0 if none was specified
	if len(options.rcodes) == 0 {
		options.rcodes[0] = struct{}{}
	}

	return nil
}

func (options *Options) configureResume() error {
	options.resumeCfg = &ResumeCfg{}
	if options.Resume && fileutil.FileExists(DefaultResumeFile) {
		return goconfig.Load(&options.resumeCfg, DefaultResumeFile)

	}
	return nil
}
