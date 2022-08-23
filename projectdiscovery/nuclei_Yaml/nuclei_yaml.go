package nuclei_Yaml

import (
	"bytes"
	"encoding/json"
	"github.com/hktalent/scan4all/lib/util"
	runner2 "github.com/hktalent/scan4all/projectdiscovery/nuclei_Yaml/nclruner/runner"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	cfgFile string
)

// 优化，不是http协议的就不走http，提高效率
// 多实例运行还是存在问题，会出现nuclei 挂起的问题
func RunNucleiP(buf *bytes.Buffer, xx chan bool, oOpts *map[string]interface{}, outNuclei chan<- *runner2.Runner) {
	if !util.GetValAsBool("enableNuclei") {
		outNuclei <- nil
		xx <- true
		return
	}
	a := strings.Split(strings.TrimSpace(buf.String()), "\n")
	var aHttp, noHttp []string
	buf.Reset()
	buf = nil
	for _, k := range a {
		if _, _, ok := util.TestIs404(k); ok {
			aHttp = append(aHttp, k)
		} else {
			noHttp = append(noHttp, k)
		}
	}
	var nucleiDone1, nucleiDone2 = make(chan bool), make(chan bool)
	util.DoSyncFunc(func() {
		defer func() { xx <- true }()
		nCnt := 0
		for {
			select {
			case _, ok := <-nucleiDone1:
				if ok {
					nCnt++
				}
				if 2 <= nCnt {
					return
				}
			case _, ok := <-nucleiDone2:
				if ok {
					nCnt++
				}
				if 2 <= nCnt {
					return
				}
			default:
			}
		}
	})
	if 0 < len(aHttp) {
		buf1 := bytes.Buffer{}
		buf1.WriteString(strings.Join(aHttp, "\n"))
		m1 := map[string]interface{}{
			// DNSProtocol,FileProtocol,NetworkProtocol,WorkflowProtocol,SSLProtocol,WebsocketProtocol,WHOISProtocol
			"Protocols":         []int{2, 3, 4, 6, 7, 8, 9},
			"EnableProgressBar": false, // 看进度条
		}
		if nil != oOpts && 0 < len(*oOpts) {
			// 指定覆盖
			data, err := json.Marshal(oOpts)
			if nil == err && 0 < len(data) {
				err := json.Unmarshal(data, &m1)
				if nil != err {
					log.Println("oOpts1 err ", err)
				}
			}
		}
		go RunNuclei(&buf1, nucleiDone1, &m1, outNuclei)
	} else {
		nucleiDone1 <- true
		close(nucleiDone1)
	}
	if 0 < len(noHttp) {
		buf1 := bytes.Buffer{}
		buf1.WriteString(strings.Join(noHttp, "\n"))
		m1 := map[string]interface{}{
			// DNSProtocol,FileProtocol,NetworkProtocol,WorkflowProtocol,SSLProtocol,WHOISProtocol
			"Protocols":         []int{1, 2, 5, 6, 7},
			"EnableProgressBar": false, // 看进度条
		}
		if nil != oOpts && 0 < len(*oOpts) {
			// 指定覆盖
			data, err := json.Marshal(oOpts)
			if nil == err && 0 < len(data) {
				err := json.Unmarshal(data, &m1)
				if nil != err {
					log.Println("oOpts2 err ", err)
				}
			}
		}
		go RunNuclei(&buf1, nucleiDone2, &m1, outNuclei)
	} else {
		nucleiDone2 <- true
		close(nucleiDone2)
	}
}

var someMapMutex = sync.RWMutex{}

func RunNuclei(buf *bytes.Buffer, xx chan bool, oOpts *map[string]interface{}, outNuclei chan<- *runner2.Runner) {
	options := &types.Options{}
	defer func() {
		xx <- true
	}()
	// json 控制参数
	options = util.ParseOption[types.Options]("nuclei", options)
	if err := runner2.ConfigureOptions(); err != nil {
		gologger.Fatal().Msgf("Could not initialize options: %s\n", err)
	}

	readConfig(options)
	options.Targets = strings.Split(strings.TrimSpace(buf.String()), "\n")
	log.Printf("options.Targets = %+v", options.Targets)
	/////////////////////////////////////
	options.Verbose = false
	options.UpdateNuclei = false
	options.Stream = false
	options.EnableProgressBar = true
	if nil != util.G_Options {
		data, err := json.Marshal(util.G_Options)
		if nil == err {
			json.Unmarshal(data, options)
		}
	}
	////////////////////////////////////*/
	someMapMutex.Lock()
	runner2.ParseOptions(options)
	someMapMutex.Unlock()
	if nil != oOpts && 0 < len(*oOpts) {
		// 指定覆盖
		data, err := json.Marshal(oOpts)
		if nil == err && 0 < len(data) {
			err := json.Unmarshal(data, options)
			if nil != err {
				log.Println("oOpts err ", err)
			}
		}
	}
	//data, err := json.Marshal(options)
	//if nil == err {
	//	fmt.Printf("%s", string(data))
	//}
	nucleiRunner, err := runner2.New(options)
	if err != nil {
		//fmt.Println(options)
		gologger.Fatal().Msgf("nucleiRunner Could not create runner: %s\n", err)
	}
	if nucleiRunner == nil {
		outNuclei <- nil
		return
	}
	defer nucleiRunner.Close()
	//data, _ := json.Marshal(options)
	//log.Printf("%+v", string(data))
	outNuclei <- nucleiRunner
	if err := nucleiRunner.RunEnumeration(); err != nil {
		if options.Validate {
			gologger.Fatal().Msgf("Could not validate templates: %s\n", err)
		} else {
			gologger.Fatal().Msgf("Could not run nuclei: %s\n", err)
		}
	}
}
func readConfig(options *types.Options) {
	pwd, _ := os.Getwd()
	options.Targets = []string{}
	options.TargetsFilePath = ""
	options.Resume = ""

	options.NewTemplates = false
	// 关闭 AutomaticScan，否则不对模版进行扫描
	options.AutomaticScan = false
	options.Templates = []string{}
	options.TemplateURLs = []string{}
	options.Workflows = []string{}
	options.WorkflowURLs = []string{}
	options.Validate = false
	options.TemplateList = false
	options.RemoteTemplateDomainList = []string{"api.nuclei.sh"}

	options.Authors = []string{}
	options.Tags = []string{}
	options.ExcludeTags = []string{"fuzz"}
	options.IncludeTags = []string{}
	options.IncludeIds = []string{}
	options.ExcludeIds = []string{}
	options.IncludeTemplates = []string{}
	options.ExcludedTemplates = []string{}

	options.Output = ""
	options.StoreResponse = false
	options.StoreResponseDir = runner2.DefaultDumpTrafficOutputFolder
	options.Silent = false
	options.NoColor = false
	options.JSON = false
	options.JSONRequests = false
	options.NoMeta = false
	options.NoTimestamp = false
	options.ReportingDB = ""
	options.MatcherStatus = false
	options.MarkdownExportDirectory = ""
	options.SarifExport = ""

	cfgFile = ""
	options.FollowRedirects = false
	options.MaxRedirects = 10
	options.DisableRedirects = true

	options.ReportingConfig = ""
	// 启动es记录
	if "true" == util.GetVal("enableEsSv") {
		options.ReportingConfig = pwd + "/config/nuclei_esConfig.yaml"
	}
	options.CustomHeaders = []string{}
	options.Vars = goflags.RuntimeMap{}
	options.ResolversFile = ""
	options.SystemResolvers = false
	options.OfflineHTTP = false
	options.EnvironmentVariables = false
	options.ClientCertFile = ""
	options.ClientKeyFile = ""
	options.ClientCAFile = ""
	options.ZTLS = false
	options.SNI = ""

	options.InteractshURL = ""
	options.InteractshToken = ""
	options.InteractionsCacheSize = 5000
	options.InteractionsEviction = 60
	options.InteractionsPollDuration = 5
	options.InteractionsCoolDownPeriod = 5
	options.NoInteractsh = false

	//createGroup(flagSet, "input", "Target",
	//	flagSet.StringSliceVarP(&options.Targets, "target", "u", []string{}, "target URLs/hosts to scan"),
	//	flagSet.StringVarP(&options.TargetsFilePath, "list", "l", "", "path to file containing a list of target URLs/hosts to scan (one per line)"),
	//	flagSet.StringVar(&options.Resume, "resume", "", "Resume scan using resume.cfg (clustering will be disabled)"),
	//)
	//
	//createGroup(flagSet, "templates", "Templates",
	//	flagSet.BoolVarP(&options.NewTemplates, "new-templates", "nt", false, "run only new templates added in latest nuclei-templates release"),
	//	flagSet.BoolVarP(&options.AutomaticScan, "automatic-scan", "as", false, "automatic web scan using wappalyzer technology detection to tags mapping"),
	//	flagSet.FileNormalizedOriginalStringSliceVarP(&options.Templates, "templates", "t", []string{}, "list of template or template directory to run (comma-separated, file)"),
	//	flagSet.FileNormalizedOriginalStringSliceVarP(&options.TemplateURLs, "template-url", "tu", []string{}, "list of template urls to run (comma-separated, file)"),
	//	flagSet.FileNormalizedOriginalStringSliceVarP(&options.Workflows, "workflows", "w", []string{}, "list of workflow or workflow directory to run (comma-separated, file)"),
	//	flagSet.FileNormalizedOriginalStringSliceVarP(&options.WorkflowURLs, "workflow-url", "wu", []string{}, "list of workflow urls to run (comma-separated, file)"),
	//	flagSet.BoolVar(&options.Validate, "validate", false, "validate the passed templates to nuclei"),
	//	flagSet.BoolVar(&options.TemplateList, "tl", false, "list all available templates"),
	//	flagSet.StringSliceVarConfigOnly(&options.RemoteTemplateDomainList, "remote-template-domain", []string{"api.nuclei.sh"}, "allowed domain list to load remote templates from"),
	//)
	//createGroup(flagSet, "filters", "Filtering",
	//flagSet.FileNormalizedStringSliceVarP(&options.Authors, "author", "a", []string{}, "templates to run based on authors (comma-separated, file)"),
	//flagSet.FileNormalizedStringSliceVar(&options.Tags, "tags", []string{}, "templates to run based on tags (comma-separated, file)"),
	//flagSet.FileNormalizedStringSliceVarP(&options.ExcludeTags, "exclude-tags", "etags", []string{}, "templates to exclude based on tags (comma-separated, file)"),
	//flagSet.FileNormalizedStringSliceVarP(&options.IncludeTags, "include-tags", "itags", []string{}, "tags to be executed even if they are excluded either by default or configuration"),
	//flagSet.FileNormalizedStringSliceVarP(&options.IncludeIds, "template-id", "id", []string{}, "templates to run based on template ids (comma-separated, file)"),
	//flagSet.FileNormalizedStringSliceVarP(&options.ExcludeIds, "exclude-id", "eid", []string{}, "templates to exclude based on template ids (comma-separated, file)"),
	//flagSet.FileNormalizedOriginalStringSliceVarP(&options.IncludeTemplates, "include-templates", "it", []string{}, "templates to be executed even if they are excluded either by default or configuration"),
	//flagSet.FileNormalizedOriginalStringSliceVarP(&options.ExcludedTemplates, "exclude-templates", "et", []string{}, "template or template directory to exclude (comma-separated, file)"),
	//flagSet.VarP(&options.Severities, "severity", "s", fmt.Sprintf("templates to run based on severity. Possible values: %s", severity.GetSupportedSeverities().String())),
	//flagSet.VarP(&options.ExcludeSeverities, "exclude-severity", "es", fmt.Sprintf("templates to exclude based on severity. Possible values: %s", severity.GetSupportedSeverities().String())),
	//flagSet.VarP(&options.Protocols, "type", "pt", fmt.Sprintf("templates to run based on protocol type. Possible values: %s", templateTypes.GetSupportedProtocolTypes())),
	//flagSet.VarP(&options.ExcludeProtocols, "exclude-type", "ept", fmt.Sprintf("templates to exclude based on protocol type. Possible values: %s", templateTypes.GetSupportedProtocolTypes())),
	//)
	options.Protocols = templateTypes.GetSupportedProtocolTypes()
	//options.ExcludeProtocols = templateTypes.GetSupportedProtocolTypes()

	//createGroup(flagSet, "output", "Output",
	//	flagSet.StringVarP(&options.Output, "output", "o", "", "output file to write found issues/vulnerabilities"),
	//	flagSet.BoolVarP(&options.StoreResponse, "store-resp", "sresp", false, "store all request/response passed through nuclei to output directory"),
	//	flagSet.StringVarP(&options.StoreResponseDir, "store-resp-dir", "srd", runner.DefaultDumpTrafficOutputFolder, "store all request/response passed through nuclei to custom directory"),
	//	flagSet.BoolVar(&options.Silent, "silent", false, "display findings only"),
	//	flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "disable output content coloring (ANSI escape codes)"),
	//	flagSet.BoolVar(&options.JSON, "json", false, "write output in JSONL(ines) format"),
	//	flagSet.BoolVarP(&options.JSONRequests, "include-rr", "irr", false, "include request/response pairs in the JSONL output (for findings only)"),
	//	flagSet.BoolVarP(&options.NoMeta, "no-meta", "nm", false, "disable printing result metadata in cli output"),
	//	flagSet.BoolVarP(&options.NoTimestamp, "no-timestamp", "nts", false, "disable printing timestamp in cli output"),
	//	flagSet.StringVarP(&options.ReportingDB, "report-db", "rdb", "", "nuclei reporting database (always use this to persist report data)"),
	//	flagSet.BoolVarP(&options.MatcherStatus, "matcher-status", "ms", false, "display match failure status"),
	//	flagSet.StringVarP(&options.MarkdownExportDirectory, "markdown-export", "me", "", "directory to export results in markdown format"),
	//	flagSet.StringVarP(&options.SarifExport, "sarif-export", "se", "", "file to export results in SARIF format"),
	//)
	//
	//createGroup(flagSet, "configs", "Configurations",
	//	flagSet.StringVar(&cfgFile, "config", "", "path to the nuclei configuration file"),
	//	flagSet.BoolVarP(&options.FollowRedirects, "follow-redirects", "fr", false, "enable following redirects for http templates"),
	//	flagSet.IntVarP(&options.MaxRedirects, "max-redirects", "mr", 10, "max number of redirects to follow for http templates"),
	//	flagSet.BoolVarP(&options.DisableRedirects, "disable-redirects", "dr", false, "disable redirects for http templates"),
	//	flagSet.StringVarP(&options.ReportingConfigReportingConfig, "report-config", "rc", "", "nuclei reporting module configuration file"), // TODO merge into the config file or rename to issue-tracking
	//	flagSet.FileStringSliceVarP(&options.CustomHeaders, "header", "H", []string{}, "custom header/cookie to include in all http request in header:value format (cli, file)"),
	//	flagSet.RuntimeMapVarP(&options.Vars, "var", "V", []string{}, "custom vars in key=value format"),
	//	flagSet.StringVarP(&options.ResolversFile, "resolvers", "r", "", "file containing resolver list for nuclei"),
	//	flagSet.BoolVarP(&options.SystemResolvers, "system-resolvers", "sr", false, "use system DNS resolving as error fallback"),
	//	flagSet.BoolVar(&options.OfflineHTTP, "passive", false, "enable passive HTTP response processing mode"),
	//	flagSet.BoolVarP(&options.EnvironmentVariables, "env-vars", "ev", false, "enable environment variables to be used in template"),
	//	flagSet.StringVarP(&options.ClientCertFile, "client-cert", "cc", "", "client certificate file (PEM-encoded) used for authenticating against scanned hosts"),
	//	flagSet.StringVarP(&options.ClientKeyFile, "client-key", "ck", "", "client key file (PEM-encoded) used for authenticating against scanned hosts"),
	//	flagSet.StringVarP(&options.ClientCAFile, "client-ca", "ca", "", "client certificate authority file (PEM-encoded) used for authenticating against scanned hosts"),
	//	flagSet.BoolVar(&options.ZTLS, "ztls", false, "use ztls library with autofallback to standard one for tls13"),
	//	flagSet.StringVar(&options.SNI, "sni", "", "tls sni hostname to use (default: input domain name)"),
	//)

	//createGroup(flagSet, "interactsh", "interactsh",
	//	flagSet.StringVarP(&options.InteractshURL, "interactsh-server", "iserver", "", fmt.Sprintf("interactsh server url for self-hosted instance (default: %s)", client.DefaultOptions.ServerURL)),
	//	flagSet.StringVarP(&options.InteractshToken, "interactsh-token", "itoken", "", "authentication token for self-hosted interactsh server"),
	//	flagSet.IntVar(&options.InteractionsCacheSize, "interactions-cache-size", 5000, "number of requests to keep in the interactions cache"),
	//	flagSet.IntVar(&options.InteractionsEviction, "interactions-eviction", 60, "number of seconds to wait before evicting requests from cache"),
	//	flagSet.IntVar(&options.InteractionsPollDuration, "interactions-poll-duration", 5, "number of seconds to wait before each interaction poll request"),
	//	flagSet.IntVar(&options.InteractionsCoolDownPeriod, "interactions-cooldown-period", 5, "extra time for interaction polling before exiting"),
	//	flagSet.BoolVarP(&options.NoInteractsh, "no-interactsh", "ni", false, "disable interactsh server for OAST testing, exclude OAST based templates"),
	//)

	options.RateLimit = 150
	options.RateLimitMinute = 0
	options.BulkSize = 64
	options.TemplateThreads = 64
	options.HeadlessBulkSize = 10
	options.HeadlessTemplateThreads = 10

	//createGroup(flagSet, "rate-limit", "Rate-Limit",
	//	flagSet.IntVarP(&options.RateLimit, "rate-limit", "rl", 150, "maximum number of requests to send per second"),
	//	flagSet.IntVarP(&options.RateLimitMinute, "rate-limit-minute", "rlm", 0, "maximum number of requests to send per minute"),
	//	flagSet.IntVarP(&options.BulkSize, "bulk-size", "bs", 25, "maximum number of hosts to be analyzed in parallel per template"),
	//	flagSet.IntVarP(&options.TemplateThreads, "concurrency", "c", 25, "maximum number of templates to be executed in parallel"),
	//	flagSet.IntVarP(&options.HeadlessBulkSize, "headless-bulk-size", "hbs", 10, "maximum number of headless hosts to be analyzed in parallel per template"),
	//	flagSet.IntVarP(&options.HeadlessTemplateThreads, "headless-concurrency", "hc", 10, "maximum number of headless templates to be executed in parallel"),
	//)

	options.Timeout = 5
	options.Retries = 1
	options.LeaveDefaultPorts = false
	options.MaxHostError = 30
	options.Project = false // 去重复，导致file missing
	options.ProjectPath = os.TempDir()
	options.StopAtFirstMatch = false
	options.Stream = false

	//createGroup(flagSet, "optimization", "Optimizations",
	//	flagSet.IntVar(&options.Timeout, "timeout", 5, "time to wait in seconds before timeout"),
	//	flagSet.IntVar(&options.Retries, "retries", 1, "number of times to retry a failed request"),
	//	flagSet.BoolVarP(&options.LeaveDefaultPorts, "leave-default-ports", "ldp", false, "leave default HTTP/HTTPS ports (eg. host:80,host:443"),
	//	flagSet.IntVarP(&options.MaxHostError, "max-host-error", "mhe", 30, "max errors for a host before skipping from scan"),
	//	flagSet.BoolVar(&options.Project, "project", false, "use a project folder to avoid sending same request multiple times"),
	//	flagSet.StringVar(&options.ProjectPath, "project-path", os.TempDir(), "set a specific project path"),
	//	flagSet.BoolVarP(&options.StopAtFirstMatch, "stop-at-first-path", "spm", false, "stop processing HTTP requests after the first match (may break template/workflow logic)"),
	//	flagSet.BoolVar(&options.Stream, "stream", false, "stream mode - start elaborating without sorting the input"),
	//)

	options.Headless = false
	options.PageTimeout = 20
	options.ShowBrowser = false
	options.UseInstalledChrome = false

	//createGroup(flagSet, "headless", "Headless",
	//	flagSet.BoolVar(&options.Headless, "headless", false, "enable templates that require headless browser support (root user on linux will disable sandbox)"),
	//	flagSet.IntVar(&options.PageTimeout, "page-timeout", 20, "seconds to wait for each page in headless mode"),
	//	flagSet.BoolVarP(&options.ShowBrowser, "show-browser", "sb", false, "show the browser on the screen when running templates with headless mode"),
	//	flagSet.BoolVarP(&options.UseInstalledChrome, "system-chrome", "sc", false, "Use local installed chrome browser instead of nuclei installed"),
	//)

	options.Debug = false
	options.DebugRequests = false
	options.DebugResponse = false
	options.Proxy = []string{}
	options.ProxyInternal = false
	options.TraceLogFile = ""
	options.ErrorLogFile = ""
	options.Version = false
	options.Verbose = false
	options.VerboseVerbose = false
	options.EnablePprof = false
	options.TemplatesVersion = false

	//createGroup(flagSet, "debug", "Debug",
	//	flagSet.BoolVar(&options.Debug, "debug", false, "show all requests and responses"),
	//	flagSet.BoolVarP(&options.DebugRequests, "debug-req", "dreq", false, "show all sent requests"),
	//	flagSet.BoolVarP(&options.DebugResponse, "debug-resp", "dresp", false, "show all received responses"),
	//	flagSet.NormalizedOriginalStringSliceVarP(&options.Proxy, "proxy", "p", []string{}, "list of http/socks5 proxy to use (comma separated or file input)"),
	//	flagSet.BoolVarP(&options.ProxyInternal, "proxy-nclruner", "pi", false, "proxy all nclruner requests"),
	//	flagSet.StringVarP(&options.TraceLogFile, "trace-log", "tlog", "", "file to write sent requests trace log"),
	//	flagSet.StringVarP(&options.ErrorLogFile, "error-log", "elog", "", "file to write sent requests error log"),
	//	flagSet.BoolVar(&options.Version, "version", false, "show nuclei version"),
	//	flagSet.BoolVarP(&options.Verbose, "verbose", "v", false, "show verbose output"),
	//	flagSet.BoolVar(&options.VerboseVerbose, "vv", false, "display templates loaded for scan"),
	//	flagSet.BoolVarP(&options.EnablePprof, "enable-pprof", "ep", false, "enable pprof debugging server"),
	//	flagSet.BoolVarP(&options.TemplatesVersion, "templates-version", "tv", false, "shows the version of the installed nuclei-templates"),
	//)

	options.UpdateNuclei = false
	options.UpdateTemplates = false
	options.TemplatesDirectory = pwd + "/config/nuclei-templates"
	// 嵌入式集成私人版本nuclei-templates 共3744个YAML POC
	if util.GetValAsBool("enablEmbedYaml") {
		options.Templates = []string{pwd + "/config/nuclei-templates"}
		options.NoUpdateTemplates = true
	} else {
		options.NoUpdateTemplates = false
	}
	options.EnableProgressBar = true
	options.StatsJSON = false
	options.StatsInterval = 5
	options.Metrics = false
	options.MetricsPort = 9092
	//createGroup(flagSet, "update", "Update",
	//	flagSet.BoolVar(&options.UpdateNuclei, "update", false, "update nuclei engine to the latest released version"),
	//	flagSet.BoolVarP(&options.UpdateTemplates, "update-templates", "ut", false, "update nuclei-templates to latest released version"),
	//	flagSet.StringVarP(&options.TemplatesDirectory, "update-directory", "ud", "", "overwrite the default directory to install nuclei-templates"),
	//	flagSet.BoolVarP(&options.NoUpdateTemplates, "disable-update-check", "duc", false, "disable automatic nuclei/templates update check"),
	//)

	//createGroup(flagSet, "stats", "Statistics",
	//	flagSet.BoolVar(&options.EnableProgressBar, "stats", false, "display statistics about the running scan"),
	//	flagSet.BoolVarP(&options.StatsJSON, "stats-json", "sj", false, "write statistics data to an output file in JSONL(ines) format"),
	//	flagSet.IntVarP(&options.StatsInterval, "stats-interval", "si", 5, "number of seconds to wait between showing a statistics update"),
	//	flagSet.BoolVarP(&options.Metrics, "metrics", "m", false, "expose nuclei metrics on a port"),
	//	flagSet.IntVarP(&options.MetricsPort, "metrics-port", "mp", 9092, "port to expose nuclei metrics on"),
	//)

	//_ = flagSet.Parse()

	if options.LeaveDefaultPorts {
		http.LeaveDefaultPorts = true
	}

	cleanupOldResumeFiles()
}

// 删除10天前文件
func cleanupOldResumeFiles() {
	root, err := config.GetConfigDir()
	if err != nil {
		return
	}
	filter := fileutil.FileFilters{
		OlderThan: 24 * time.Hour * 10, // cleanup on the 10th day
		Prefix:    "resume-",
	}
	_ = fileutil.DeleteFilesOlderThan(root, filter)
}

//func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
//	flagSet.SetGroup(groupName, description)
//	for _, currentFlag := range flags {
//		currentFlag.Group(groupName)
//	}
//}
