package runner

import (
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/GhostTroops/scan4all/pkg/httpx/common/customheader"
	"github.com/GhostTroops/scan4all/pkg/httpx/common/customlist"
	customport "github.com/GhostTroops/scan4all/pkg/httpx/common/customports"
	fileutilz "github.com/GhostTroops/scan4all/pkg/httpx/common/fileutil"
	"github.com/GhostTroops/scan4all/pkg/httpx/common/slice"
	"github.com/GhostTroops/scan4all/pkg/httpx/common/stringz"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/goconfig"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"math"
	"os"
	"regexp"
	"strings"
)

const (
	// The maximum file length is 251 (255 - 4 bytes for ".ext" suffix)
	maxFileNameLength      = 251
	two                    = 2
	DefaultResumeFile      = "resume.cfg"
	DefaultOutputDirectory = "output"
)

type NormalizedStringSlice []string
type scanOptions struct {
	Methods                   []string
	StoreResponseDirectory    string
	RequestURI                string
	RequestBody               string
	VHost                     bool
	OutputTitle               bool
	OutputStatusCode          bool
	OutputLocation            bool
	OutputContentLength       bool
	StoreResponse             bool
	OutputServerHeader        bool
	OutputWebSocket           bool
	OutputWithNoColor         bool
	OutputMethod              bool
	ResponseInStdout          bool
	ChainInStdout             bool
	TLSProbe                  bool
	CSPProbe                  bool
	VHostInput                bool
	OutputContentType         bool
	Unsafe                    bool
	Pipeline                  bool
	HTTP2Probe                bool
	OutputIP                  bool
	OutputCName               bool
	OutputCDN                 bool
	OutputResponseTime        bool
	PreferHTTPS               bool
	NoFallback                bool
	NoFallbackScheme          bool
	TechDetect                bool
	StoreChain                bool
	MaxResponseBodySizeToSave int
	MaxResponseBodySizeToRead int
	OutputExtractRegex        string
	extractRegex              *regexp.Regexp
	ExcludeCDN                bool
	HostMaxErrors             int
	ProbeAllIPS               bool
	Favicon                   bool
	LeaveDefaultPorts         bool
	OutputLinesCount          bool
	OutputWordsCount          bool
	Hashes                    string
	//
	CeyeApi    string
	CeyeDomain string
	NoPOC      bool
}

func (s *scanOptions) Clone() *scanOptions {
	return &scanOptions{
		Methods:                   s.Methods,
		StoreResponseDirectory:    s.StoreResponseDirectory,
		RequestURI:                s.RequestURI,
		RequestBody:               s.RequestBody,
		VHost:                     s.VHost,
		OutputTitle:               s.OutputTitle,
		OutputStatusCode:          s.OutputStatusCode,
		OutputLocation:            s.OutputLocation,
		OutputContentLength:       s.OutputContentLength,
		StoreResponse:             s.StoreResponse,
		OutputServerHeader:        s.OutputServerHeader,
		OutputWebSocket:           s.OutputWebSocket,
		OutputWithNoColor:         s.OutputWithNoColor,
		OutputMethod:              s.OutputMethod,
		ResponseInStdout:          s.ResponseInStdout,
		ChainInStdout:             s.ChainInStdout,
		TLSProbe:                  s.TLSProbe,
		CSPProbe:                  s.CSPProbe,
		OutputContentType:         s.OutputContentType,
		Unsafe:                    s.Unsafe,
		Pipeline:                  s.Pipeline,
		HTTP2Probe:                s.HTTP2Probe,
		OutputIP:                  s.OutputIP,
		OutputCName:               s.OutputCName,
		OutputCDN:                 s.OutputCDN,
		OutputResponseTime:        s.OutputResponseTime,
		PreferHTTPS:               s.PreferHTTPS,
		NoFallback:                s.NoFallback,
		NoFallbackScheme:          s.NoFallbackScheme,
		TechDetect:                s.TechDetect,
		StoreChain:                s.StoreChain,
		OutputExtractRegex:        s.OutputExtractRegex,
		MaxResponseBodySizeToSave: s.MaxResponseBodySizeToSave,
		MaxResponseBodySizeToRead: s.MaxResponseBodySizeToRead,
		HostMaxErrors:             s.HostMaxErrors,
		Favicon:                   s.Favicon,
		LeaveDefaultPorts:         s.LeaveDefaultPorts,
		OutputLinesCount:          s.OutputLinesCount,
		OutputWordsCount:          s.OutputWordsCount,
		Hashes:                    s.Hashes,
	}
}

// Options contains configuration options for httpx.
type Options struct {
	CustomHeaders             customheader.CustomHeaders
	CustomPorts               customport.CustomPorts
	matchStatusCode           []int
	matchContentLength        []int
	filterStatusCode          []int
	filterContentLength       []int
	Output                    string
	StoreResponseDir          string
	HTTPProxy                 string
	SocksProxy                string
	InputFile                 string
	Methods                   string
	RequestURI                string
	RequestURIs               string
	requestURIs               []string
	OutputMatchStatusCode     string
	OutputMatchContentLength  string
	OutputFilterStatusCode    string
	OutputFilterContentLength string
	InputRawRequest           string
	rawRequest                string
	RequestBody               string
	OutputFilterString        string
	OutputMatchString         string
	OutputFilterRegex         string
	OutputMatchRegex          string
	Retries                   int
	Threads                   int
	Timeout                   int
	filterRegex               *regexp.Regexp
	matchRegex                *regexp.Regexp
	VHost                     bool
	VHostInput                bool
	Smuggling                 bool
	ExtractTitle              bool
	StatusCode                bool
	Location                  bool
	ContentLength             bool
	FollowRedirects           bool
	StoreResponse             bool
	JSONOutput                bool
	CSVOutput                 bool
	Silent                    bool
	Version                   bool
	Verbose                   bool
	NoColor                   bool
	OutputServerHeader        bool
	OutputWebSocket           bool
	responseInStdout          bool
	chainInStdout             bool
	FollowHostRedirects       bool
	MaxRedirects              int
	OutputMethod              bool
	TLSProbe                  bool
	CSPProbe                  bool
	OutputContentType         bool
	OutputIP                  bool
	OutputCName               bool
	Unsafe                    bool
	Debug                     bool
	DebugRequests             bool
	DebugResponse             bool
	Pipeline                  bool
	HTTP2Probe                bool
	OutputCDN                 bool
	OutputResponseTime        bool
	NoFallback                bool
	NoFallbackScheme          bool
	TechDetect                bool
	TLSGrab                   bool
	protocol                  string
	ShowStatistics            bool
	StatsInterval             int
	RandomAgent               bool
	StoreChain                bool
	Deny                      customlist.CustomList
	Allow                     customlist.CustomList
	MaxResponseBodySizeToSave int
	MaxResponseBodySizeToRead int
	OutputExtractRegex        string
	RateLimit                 int
	RateLimitMinute           int
	Probe                     bool
	Resume                    bool
	resumeCfg                 *ResumeCfg
	ExcludeCDN                bool
	HostMaxErrors             int
	Stream                    bool
	SkipDedupe                bool
	ProbeAllIPS               bool
	Resolvers                 NormalizedStringSlice
	Favicon                   bool
	OutputFilterFavicon       NormalizedStringSlice
	OutputMatchFavicon        NormalizedStringSlice
	LeaveDefaultPorts         bool
	OutputLinesCount          bool
	OutputMatchLinesCount     string
	matchLinesCount           []int
	OutputFilterLinesCount    string
	filterLinesCount          []int
	OutputWordsCount          bool
	OutputMatchWordsCount     string
	matchWordsCount           []int
	OutputFilterWordsCount    string
	filterWordsCount          []int
	Hashes                    string
	Jarm                      bool
	Asn                       bool
	//
	CeyeApi    string
	CeyeDomain string
	NoPOC      bool
}

// ParseOptions parses the command line options for application
func ParseOptions() *Options {
	options := &Options{}

	options.InputFile = ""
	options.InputRawRequest = ""
	options.StatusCode = true
	options.ContentLength = false
	options.OutputContentType = false
	options.Location = false
	options.Favicon = true
	options.Hashes = ""
	options.Jarm = false
	options.OutputResponseTime = false
	options.OutputLinesCount = false
	options.OutputWordsCount = false
	options.ExtractTitle = true
	options.OutputServerHeader = true
	options.TechDetect = true
	options.OutputMethod = true
	options.OutputWebSocket = true
	options.OutputIP = true
	options.OutputCName = false
	options.Asn = false
	options.OutputCDN = false
	options.Probe = false
	options.OutputMatchStatusCode = ""
	options.OutputMatchContentLength = ""
	options.OutputMatchLinesCount = ""
	options.OutputMatchWordsCount = ""
	options.OutputMatchFavicon = []string{}
	options.OutputMatchString = ""
	options.OutputMatchRegex = ""
	options.OutputExtractRegex = ""
	options.OutputFilterStatusCode = "400,404,500"
	options.OutputFilterContentLength = ""
	options.OutputFilterLinesCount = ""
	options.OutputFilterWordsCount = ""
	options.OutputFilterFavicon = []string{}
	options.OutputFilterString = ""
	options.OutputFilterRegex = ""
	options.Threads = 50
	options.RateLimit = 150
	options.RateLimitMinute = 0
	options.ProbeAllIPS = false
	options.CustomPorts = nil
	options.RequestURIs = ""
	options.TLSProbe = false
	options.CSPProbe = false
	options.TLSGrab = false
	options.Pipeline = false
	options.HTTP2Probe = false
	options.VHost = false
	options.Output = ""
	options.StoreResponse = false
	options.StoreResponseDir = ""
	options.CSVOutput = false
	options.JSONOutput = false
	options.responseInStdout = false
	options.chainInStdout = false
	options.StoreChain = false
	options.Resolvers = []string{}
	options.Allow = nil
	options.Deny = nil
	options.RandomAgent = true
	options.CustomHeaders = nil
	options.HTTPProxy = ""
	options.Unsafe = false
	options.Resume = false
	options.FollowRedirects = false
	options.MaxRedirects = 3
	options.FollowHostRedirects = false
	options.VHostInput = false
	options.Methods = ""
	options.RequestBody = ""
	options.Stream = false
	options.SkipDedupe = false
	options.LeaveDefaultPorts = false
	options.Debug = false
	options.DebugRequests = false
	options.DebugResponse = false
	options.Version = false
	options.ShowStatistics = false
	options.Silent = false
	options.Verbose = false
	options.StatsInterval = 0
	options.NoColor = false
	options.NoFallback = false
	options.NoFallbackScheme = false
	options.HostMaxErrors = 30
	options.ExcludeCDN = false
	options.Retries = 0
	options.Timeout = 5
	options.MaxResponseBodySizeToSave = math.MaxInt32
	options.MaxResponseBodySizeToRead = math.MaxInt32

	if options.StatsInterval != 0 {
		options.ShowStatistics = true
	}

	// Read the inputs and configure the logging
	options.configureOutput()

	err := options.configureResume()
	if err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	//showBanner()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", util.Version)
		os.Exit(0)
	}

	options.validateOptions()

	return options
}

func (options *Options) validateOptions() {
	if options.InputFile != "" && !fileutilz.FileNameIsGlob(options.InputFile) && !fileutil.FileExists(options.InputFile) {
		gologger.Fatal().Msgf("File %s does not exist.\n", options.InputFile)
	}

	if options.InputRawRequest != "" && !fileutil.FileExists(options.InputRawRequest) {
		gologger.Fatal().Msgf("File %s does not exist.\n", options.InputRawRequest)
	}

	multiOutput := options.CSVOutput && options.JSONOutput
	if multiOutput {
		gologger.Fatal().Msg("Results can only be displayed in one format: 'JSON' or 'CSV'\n")
	}

	var err error
	if options.matchStatusCode, err = stringz.StringToSliceInt(options.OutputMatchStatusCode); err != nil {
		gologger.Fatal().Msgf("Invalid value for match status code option: %s\n", err)
	}
	if options.matchContentLength, err = stringz.StringToSliceInt(options.OutputMatchContentLength); err != nil {
		gologger.Fatal().Msgf("Invalid value for match content length option: %s\n", err)
	}
	if options.filterStatusCode, err = stringz.StringToSliceInt(options.OutputFilterStatusCode); err != nil {
		gologger.Fatal().Msgf("Invalid value for filter status code option: %s\n", err)
	}
	if options.filterContentLength, err = stringz.StringToSliceInt(options.OutputFilterContentLength); err != nil {
		gologger.Fatal().Msgf("Invalid value for filter content length option: %s\n", err)
	}
	if options.OutputFilterRegex != "" {
		if options.filterRegex, err = regexp.Compile(options.OutputFilterRegex); err != nil {
			gologger.Fatal().Msgf("Invalid value for regex filter option: %s\n", err)
		}
	}
	if options.OutputMatchRegex != "" {
		if options.matchRegex, err = regexp.Compile(options.OutputMatchRegex); err != nil {
			gologger.Fatal().Msgf("Invalid value for match regex option: %s\n", err)
		}
	}
	if options.matchLinesCount, err = stringz.StringToSliceInt(options.OutputMatchLinesCount); err != nil {
		gologger.Fatal().Msgf("Invalid value for match lines count option: %s\n", err)
	}
	if options.matchWordsCount, err = stringz.StringToSliceInt(options.OutputMatchWordsCount); err != nil {
		gologger.Fatal().Msgf("Invalid value for match words count option: %s\n", err)
	}
	if options.filterLinesCount, err = stringz.StringToSliceInt(options.OutputFilterLinesCount); err != nil {
		gologger.Fatal().Msgf("Invalid value for filter lines count option: %s\n", err)
	}
	if options.filterWordsCount, err = stringz.StringToSliceInt(options.OutputFilterWordsCount); err != nil {
		gologger.Fatal().Msgf("Invalid value for filter words count option: %s\n", err)
	}

	var resolvers []string
	for _, resolver := range options.Resolvers {
		if fileutil.FileExists(resolver) {
			chFile, err := fileutil.ReadFile(resolver)
			if err != nil {
				gologger.Fatal().Msgf("Couldn't process resolver file \"%s\": %s\n", resolver, err)
			}
			for line := range chFile {
				resolvers = append(resolvers, line)
			}
		} else {
			resolvers = append(resolvers, resolver)
		}
	}
	options.Resolvers = resolvers
	if len(options.Resolvers) > 0 {
		gologger.Debug().Msgf("Using resolvers: %s\n", strings.Join(options.Resolvers, ","))
	}

	if options.StoreResponse && options.StoreResponseDir == "" {
		gologger.Debug().Msgf("Store response directory not specified, using \"%s\"\n", DefaultOutputDirectory)
		options.StoreResponseDir = DefaultOutputDirectory
	}
	if options.StoreResponseDir != "" && !options.StoreResponse {
		gologger.Debug().Msgf("Store response directory specified, enabling \"sr\" flag automatically\n")
		options.StoreResponse = true
	}

	if options.Favicon {
		gologger.Debug().Msgf("Setting single path to \"favicon.ico\" and ignoring multiple paths settings\n")
		options.RequestURIs = "/favicon.ico"
	}

	if options.Hashes != "" {
		for _, hashType := range strings.Split(options.Hashes, ",") {
			if !slice.StringSliceContains([]string{"md5", "sha1", "sha256", "sha512", "mmh3", "simhash"}, strings.ToLower(hashType)) {
				gologger.Error().Msgf("Unsupported hash type: %s\n", hashType)
			}
		}
	}
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
	if options.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}

func (options *Options) configureResume() error {
	options.resumeCfg = &ResumeCfg{}
	if options.Resume && fileutil.FileExists(DefaultResumeFile) {
		return goconfig.Load(&options.resumeCfg, DefaultResumeFile)

	}
	return nil
}

// ShouldLoadResume resume file
func (options *Options) ShouldLoadResume() bool {
	return options.Resume && fileutil.FileExists(DefaultResumeFile)
}

// ShouldSaveResume file
func (options *Options) ShouldSaveResume() bool {
	return true
}

func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	flagSet.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}
