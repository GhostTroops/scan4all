package runner

import (
	"math"
	"os"
	"regexp"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/goconfig"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/veo/vscan/pkg/httpx/common/customheader"
	"github.com/veo/vscan/pkg/httpx/common/customlist"
	customport "github.com/veo/vscan/pkg/httpx/common/customports"
	fileutilz "github.com/veo/vscan/pkg/httpx/common/fileutil"
	"github.com/veo/vscan/pkg/httpx/common/stringz"
)

const (
	maxFileNameLength = 255
	two               = 2
	DefaultResumeFile = "resume.cfg"
)

type scanOptions struct {
	Methods                   []string
	StoreResponseDirectory    string
	RequestURI                string
	RequestBody               string
	VHost                     bool
	CeyeApi                   string
	CeyeDomain                string
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
	CeyeApi                   string
	CeyeDomain                string
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
	RandomAgent               bool
	StoreChain                bool
	Deny                      customlist.CustomList
	Allow                     customlist.CustomList
	MaxResponseBodySizeToSave int
	MaxResponseBodySizeToRead int
	OutputExtractRegex        string
	RateLimit                 int
	Probe                     bool
	Resume                    bool
	resumeCfg                 *ResumeCfg
	ExcludeCDN                bool
	HostMaxErrors             int
	Stream                    bool
	SkipDedupe                bool
	Naabuinput                map[string]map[int]struct{}
}

// ParseOptions parses the command line options for application
func ParseOptions() *Options {
	options := &Options{}
	options.InputFile = ""
	options.InputRawRequest = ""
	options.StatusCode = true
	options.TechDetect = true
	options.ContentLength = false
	options.OutputServerHeader = false
	options.OutputContentType = false
	options.OutputResponseTime = false
	options.ExtractTitle = true
	options.Location = false
	options.OutputMethod = false
	options.OutputWebSocket = false
	options.OutputIP = false
	options.OutputCName = false
	options.OutputCDN = false
	options.Probe = false
	options.NoFallback = false
	options.OutputMatchStatusCode = ""
	options.OutputMatchContentLength = ""
	options.OutputMatchString = ""
	options.OutputMatchRegex = ""
	options.OutputExtractRegex = ""
	options.OutputFilterStatusCode = ""
	options.OutputFilterContentLength = ""
	options.OutputFilterString = ""
	options.OutputFilterRegex = ""
	options.Threads = 50
	options.RateLimit = 150
	options.TLSGrab = false
	options.TLSProbe = false
	options.CSPProbe = false
	options.Pipeline = false
	options.HTTP2Probe = false
	options.VHost = false
	options.CustomPorts = nil
	options.RequestURIs = ""
	options.RequestURIs = ""
	options.Output = ""
	options.StoreResponse = false
	options.StoreResponseDir = "output"
	options.JSONOutput = false
	options.responseInStdout = false
	options.chainInStdout = false
	options.StoreChain = false
	options.CSVOutput = false
	options.MaxResponseBodySizeToSave = math.MaxInt32
	options.MaxResponseBodySizeToRead = math.MaxInt32
	options.Allow = nil
	options.Deny = nil
	options.RandomAgent = true
	options.CustomHeaders = nil
	options.HTTPProxy = ""
	options.CeyeApi = ""
	options.CeyeDomain = ""
	options.Unsafe = false
	options.Resume = false
	options.NoColor = false
	options.NoFallbackScheme = false
	options.FollowRedirects = true
	options.FollowHostRedirects = false
	options.MaxRedirects = 10
	options.VHostInput = false
	options.Methods = ""
	options.RequestBody = ""
	options.Stream = false
	options.SkipDedupe = false
	options.Silent = true
	options.Verbose = false
	options.Version = false
	options.Debug = false
	options.ShowStatistics = false
	options.Retries = 0
	options.Timeout = 5
	options.HostMaxErrors = 30
	options.ExcludeCDN = false
	options.Naabuinput = nil

	options.configureOutput()

	err := options.configureResume()
	if err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	//showBanner()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", Version)
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

//func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
//	flagSet.SetGroup(groupName, description)
//	for _, currentFlag := range flags {
//		currentFlag.Group(groupName)
//	}
//}
