package libs

// Options global options
type Options struct {
	RootFolder          string
	SignFolder          string
	PassiveFolder       string
	ResourcesFolder     string
	ThirdPartyFolder    string
	ScanID              string
	ConfigFile          string
	FoundCmd            string
	QuietFormat         string
	PassiveOutput       string
	PassiveSummary      string
	Output              string
	SummaryOutput       string
	SummaryVuln         string
	LogFile             string
	Proxy               string
	Selectors           string
	InlineDetection     string
	Params              []string
	Headers             []string
	Signs               []string
	Excludes            []string
	SelectedSigns       []string
	ParsedSelectedSigns []Signature
	ParallelSigns       []string
	SelectedPassive     string
	GlobalVar           map[string]string

	Level             int
	Concurrency       int
	Threads           int
	Delay             int
	Timeout           int
	Refresh           int
	Retry             int
	SaveRaw           bool
	LocalAnalyze      bool
	JsonOutput        bool
	VerboseSummary    bool
	Quiet             bool
	FullHelp          bool
	Verbose           bool
	Version           bool
	Debug             bool
	NoDB              bool
	NoBackGround      bool
	NoOutput          bool
	EnableFormatInput bool
	EnablePassive     bool
	DisableParallel   bool

	// only enable when doing sensitive mode
	EnableFiltering bool
	// for DNS
	Resolver string

	// Chunk Options
	ChunkDir     string
	ChunkRun     bool
	ChunkThreads int
	ChunkSize    int
	ChunkLimit   int

	Mics   Mics
	Scan   Scan
	Server Server
	Report Report
	Config Config
}

// Scan options for api server
type Scan struct {
	RawRequest      string
	EnableGenReport bool
}

// Mics some shortcut options
type Mics struct {
	FullHelp         bool
	AlwaysTrue       bool
	BaseRoot         bool
	BurpProxy        bool
	DisableReplicate bool
}

// Report options for api server
type Report struct {
	VerboseReport bool
	ReportName    string
	TemplateFile  string
	VTemplateFile string
	OutputPath    string
	Title         string
}

// Server options for api server
type Server struct {
	NoAuth       bool
	DBPath       string
	Bind         string
	JWTSecret    string
	Cors         string
	DefaultSign  string
	SecretCollab string
	Username     string
	Password     string
	Key          string
}

// Config options for api server
type Config struct {
	Forced     bool
	SkipMics   bool
	Username   string
	Password   string
	Repo       string
	PrivateKey string
}

// Job define job for running routine
type Job struct {
	URL       string
	Checksums []string
	Sign      Signature
	// the base response
	Response Response
}

// VulnData vulnerable Data
type VulnData struct {
	ScanID          string
	SignID          string
	SignName        string
	URL             string
	Risk            string
	DetectionString string
	DetectResult    string
	Confidence      string
	Req             string
	Res             string
	// little information
	StatusCode    string
	ContentLength string
	OutputFile    string
	SignatureFile string
}
