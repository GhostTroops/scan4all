package runner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"nuclei/v2/nuclei/runner/nucleicloud"

	"github.com/blang/semver"
	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/ratelimit"
	"go.uber.org/atomic"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v2/pkg/core"
	"github.com/projectdiscovery/nuclei/v2/pkg/core/inputs/hybrid"
	"github.com/projectdiscovery/nuclei/v2/pkg/external/customtemplates"
	"github.com/projectdiscovery/nuclei/v2/pkg/input"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v2/pkg/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/projectfile"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/automaticscan"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/uncover"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/utils/excludematchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/headless/engine"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/exporters/markdown"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/exporters/sarif"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils/stats"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils/yaml"
	yamlwrapper "github.com/projectdiscovery/nuclei/v2/pkg/utils/yaml"
	"github.com/projectdiscovery/retryablehttp-go"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"nuclei/v2/nuclei/colorizer"
)

// Runner is a client for running the enumeration process.
type Runner struct {
	output            output.Writer
	interactsh        *interactsh.Client
	templatesConfig   *config.Config
	options           *types.Options
	projectFile       *projectfile.ProjectFile
	catalog           catalog.Catalog
	progress          progress.Progress
	colorizer         aurora.Aurora
	issuesClient      *reporting.Client
	hmapInputProvider *hybrid.Input
	browser           *engine.Browser
	ratelimiter       *ratelimit.Limiter
	hostErrors        hosterrorscache.CacheInterface
	resumeCfg         *types.ResumeCfg
	pprofServer       *http.Server
	customTemplates   []customtemplates.Provider
	cloudClient       *nucleicloud.Client
	cloudTargets      []string
}

const pprofServerAddress = "127.0.0.1:8086"

// New creates a new client for running enumeration process.
func New(options *types.Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}

	if options.HealthCheck {
		gologger.Print().Msgf("%s\n", DoHealthCheck(options))
		os.Exit(0)
	}

	if options.Cloud {
		runner.cloudClient = nucleicloud.New(options.CloudURL, options.CloudAPIKey)
	}

	if options.UpdateNuclei {
		if err := updateNucleiVersionToLatest(runner.options.Verbose); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if options.Validate {
		parsers.ShouldValidate = true
		// Does not update the templates when validate flag is used
		options.NoUpdateTemplates = true
	}

	// TODO: refactor to pass options reference globally without cycles
	parsers.NoStrictSyntax = options.NoStrictSyntax
	yaml.StrictSyntax = !options.NoStrictSyntax

	// parse the runner.options.GithubTemplateRepo and store the valid repos in runner.customTemplateRepos
	runner.customTemplates = customtemplates.ParseCustomTemplates(runner.options)

	if err := runner.updateTemplates(); err != nil {
		gologger.Error().Msgf("Could not update templates: %s\n", err)
	}
	if options.Headless {
		if engine.MustDisableSandbox() {
			gologger.Warning().Msgf("The current platform and privileged user will run the browser without sandbox\n")
		}
		browser, err := engine.New(options)
		if err != nil {
			return nil, err
		}
		runner.browser = browser
	}

	runner.catalog = disk.NewCatalog(runner.options.TemplatesDirectory)

	var httpclient *retryablehttp.Client
	if options.ProxyInternal && types.ProxyURL != "" || types.ProxySocksURL != "" {
		var err error
		httpclient, err = httpclientpool.Get(options, &httpclientpool.Configuration{})
		if err != nil {
			return nil, err
		}
	}

	if err := reporting.CreateConfigIfNotExists(); err != nil {
		return nil, err
	}
	reportingOptions, err := createReportingOptions(options)
	if err != nil {
		return nil, err
	}
	if reportingOptions != nil && httpclient != nil {
		reportingOptions.HttpClient = httpclient
	}

	if reportingOptions != nil {
		client, err := reporting.New(reportingOptions, options.ReportingDB)
		if err != nil {
			return nil, errors.Wrap(err, "could not create issue reporting client")
		}
		runner.issuesClient = client
	}

	// output coloring
	useColor := !options.NoColor
	runner.colorizer = aurora.NewAurora(useColor)
	templates.Colorizer = runner.colorizer
	templates.SeverityColorizer = colorizer.New(runner.colorizer)

	if options.EnablePprof {
		server := &http.Server{
			Addr:    pprofServerAddress,
			Handler: http.DefaultServeMux,
		}
		gologger.Info().Msgf("Listening pprof debug server on: %s", pprofServerAddress)
		runner.pprofServer = server
		go func() {
			_ = server.ListenAndServe()
		}()
	}

	if (len(options.Templates) == 0 || !options.NewTemplates || (options.TargetsFilePath == "" && !options.Stdin && len(options.Targets) == 0)) && (options.UpdateTemplates && !options.Cloud) {
		os.Exit(0)
	}

	// Initialize the input source
	hmapInput, err := hybrid.New(&hybrid.Options{
		Options: options,
		NotFoundCallback: func(target string) bool {
			parsed, parseErr := strconv.ParseInt(target, 10, 64)
			if parseErr != nil {
				if err := runner.cloudClient.ExistsDataSourceItem(nucleicloud.ExistsDataSourceItemRequest{Contents: target, Type: "targets"}); err == nil {
					runner.cloudTargets = append(runner.cloudTargets, target)
					return true
				}
				return false
			}
			if exists, err := runner.cloudClient.ExistsTarget(parsed); err == nil {
				runner.cloudTargets = append(runner.cloudTargets, exists.Reference)
				return true
			}
			return false
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not create input provider")
	}
	runner.hmapInputProvider = hmapInput

	// Create the output file if asked
	outputWriter, err := output.NewStandardWriter(options)
	if err != nil {
		return nil, errors.Wrap(err, "could not create output file")
	}
	runner.output = outputWriter

	if options.JSON && options.EnableProgressBar {
		options.StatsJSON = true
	}
	if options.StatsJSON {
		options.EnableProgressBar = true
	}
	// Creates the progress tracking object
	var progressErr error
	runner.progress, progressErr = progress.NewStatsTicker(options.StatsInterval, options.EnableProgressBar, options.StatsJSON, options.Metrics, options.MetricsPort)
	if progressErr != nil {
		return nil, progressErr
	}

	// create project file if requested or load the existing one
	if options.Project {
		var projectFileErr error
		runner.projectFile, projectFileErr = projectfile.New(&projectfile.Options{Path: options.ProjectPath, Cleanup: utils.IsBlank(options.ProjectPath)})
		if projectFileErr != nil {
			return nil, projectFileErr
		}
	}

	// create the resume configuration structure
	resumeCfg := types.NewResumeCfg()
	if runner.options.ShouldLoadResume() {
		gologger.Info().Msg("Resuming from save checkpoint")
		file, err := os.ReadFile(runner.options.Resume)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal([]byte(file), &resumeCfg)
		if err != nil {
			return nil, err
		}
		resumeCfg.Compile()
	}
	runner.resumeCfg = resumeCfg

	opts := interactsh.NewDefaultOptions(runner.output, runner.issuesClient, runner.progress)
	opts.Debug = runner.options.Debug
	opts.NoColor = runner.options.NoColor
	if options.InteractshURL != "" {
		opts.ServerURL = options.InteractshURL
	}
	opts.Authorization = options.InteractshToken
	opts.CacheSize = int64(options.InteractionsCacheSize)
	opts.Eviction = time.Duration(options.InteractionsEviction) * time.Second
	opts.CooldownPeriod = time.Duration(options.InteractionsCoolDownPeriod) * time.Second
	opts.PollDuration = time.Duration(options.InteractionsPollDuration) * time.Second
	opts.NoInteractsh = runner.options.NoInteractsh
	opts.StopAtFirstMatch = runner.options.StopAtFirstMatch
	opts.Debug = runner.options.Debug
	opts.DebugRequest = runner.options.DebugRequests
	opts.DebugResponse = runner.options.DebugResponse
	if httpclient != nil {
		opts.HTTPClient = httpclient
	}
	interactshClient, err := interactsh.New(opts)
	if err != nil {
		gologger.Error().Msgf("Could not create interactsh client: %s", err)
	} else {
		runner.interactsh = interactshClient
	}

	if options.RateLimitMinute > 0 {
		runner.ratelimiter = ratelimit.New(context.Background(), uint(options.RateLimitMinute), time.Minute)
	} else if options.RateLimit > 0 {
		runner.ratelimiter = ratelimit.New(context.Background(), uint(options.RateLimit), time.Second)
	} else {
		runner.ratelimiter = ratelimit.NewUnlimited(context.Background())
	}
	return runner, nil
}

func createReportingOptions(options *types.Options) (*reporting.Options, error) {
	var reportingOptions *reporting.Options
	if options.ReportingConfig != "" {
		file, err := os.Open(options.ReportingConfig)
		if err != nil {
			return nil, errors.Wrap(err, "could not open reporting config file")
		}

		reportingOptions = &reporting.Options{}
		if err := yamlwrapper.DecodeAndValidate(file, reportingOptions); err != nil {
			file.Close()
			return nil, errors.Wrap(err, "could not parse reporting config file")
		}
		file.Close()
	}
	if options.MarkdownExportDirectory != "" {
		if reportingOptions != nil {
			reportingOptions.MarkdownExporter = &markdown.Options{Directory: options.MarkdownExportDirectory}
		} else {
			reportingOptions = &reporting.Options{}
			reportingOptions.MarkdownExporter = &markdown.Options{Directory: options.MarkdownExportDirectory}
		}
	}
	if options.SarifExport != "" {
		if reportingOptions != nil {
			reportingOptions.SarifExporter = &sarif.Options{File: options.SarifExport}
		} else {
			reportingOptions = &reporting.Options{}
			reportingOptions.SarifExporter = &sarif.Options{File: options.SarifExport}
		}
	}
	return reportingOptions, nil
}

// Close releases all the resources and cleans up
func (r *Runner) Close() {
	if r.output != nil {
		r.output.Close()
	}
	if r.projectFile != nil {
		r.projectFile.Close()
	}
	r.hmapInputProvider.Close()
	protocolinit.Close()
	if r.pprofServer != nil {
		_ = r.pprofServer.Shutdown(context.Background())
	}
	if r.ratelimiter != nil {
		r.ratelimiter.Stop()
	}
}

// RunEnumeration sets up the input layer for giving input nuclei.
// binary and runs the actual enumeration
func (r *Runner) RunEnumeration() error {
	defer r.Close()

	// If user asked for new templates to be executed, collect the list from the templates' directory.
	if r.options.NewTemplates {
		templatesLoaded, err := r.readNewTemplatesFile()
		if err != nil {
			return errors.Wrap(err, "could not get newly added templates")
		}
		r.options.Templates = append(r.options.Templates, templatesLoaded...)
	}
	if len(r.options.NewTemplatesWithVersion) > 0 {
		minVersion, err := semver.Parse("8.8.4")
		if err != nil {
			return errors.Wrap(err, "could not parse minimum version")
		}
		latestVersion, err := semver.Parse(r.templatesConfig.NucleiTemplatesLatestVersion)
		if err != nil {
			return errors.Wrap(err, "could not get latest version")
		}
		for _, version := range r.options.NewTemplatesWithVersion {
			current, err := semver.Parse(strings.Trim(version, "v"))
			if err != nil {
				return errors.Wrap(err, "could not parse current version")
			}
			if !(current.GT(minVersion) && current.LTE(latestVersion)) {
				return fmt.Errorf("version should be greater than %s and less than %s", minVersion, latestVersion)
			}
			templatesLoaded, err := r.readNewTemplatesWithVersionFile(fmt.Sprintf("v%s", current))
			if err != nil {
				return errors.Wrap(err, "could not get newly added templates for "+current.String())
			}
			r.options.Templates = append(r.options.Templates, templatesLoaded...)
		}
	}
	// Exclude ignored file for validation
	if !r.options.Validate {
		ignoreFile := config.ReadIgnoreFile()
		r.options.ExcludeTags = append(r.options.ExcludeTags, ignoreFile.Tags...)
		r.options.ExcludedTemplates = append(r.options.ExcludedTemplates, ignoreFile.Files...)
	}
	var cache *hosterrorscache.Cache
	if r.options.MaxHostError > 0 {
		cache = hosterrorscache.New(r.options.MaxHostError, hosterrorscache.DefaultMaxHostsCount)
		cache.SetVerbose(r.options.Verbose)
	}
	r.hostErrors = cache

	// Create the executer options which will be used throughout the execution
	// stage by the nuclei engine modules.
	executerOpts := protocols.ExecuterOptions{
		Output:          r.output,
		Options:         r.options,
		Progress:        r.progress,
		Catalog:         r.catalog,
		IssuesClient:    r.issuesClient,
		RateLimiter:     r.ratelimiter,
		Interactsh:      r.interactsh,
		ProjectFile:     r.projectFile,
		Browser:         r.browser,
		HostErrorsCache: cache,
		Colorizer:       r.colorizer,
		ResumeCfg:       r.resumeCfg,
		ExcludeMatchers: excludematchers.New(r.options.ExcludeMatchers),
		InputHelper:     input.NewHelper(),
	}
	engine := core.New(r.options)
	engine.SetExecuterOptions(executerOpts)

	workflowLoader, err := parsers.NewLoader(&executerOpts)
	if err != nil {
		return errors.Wrap(err, "Could not create loader.")
	}
	executerOpts.WorkflowLoader = workflowLoader

	templateConfig := r.templatesConfig
	if templateConfig == nil {
		templateConfig = &config.Config{}
	}

	store, err := loader.New(loader.NewConfig(r.options, templateConfig, r.catalog, executerOpts))
	if err != nil {
		return errors.Wrap(err, "could not load templates from config")
	}

	var cloudTemplates []string
	if r.options.Cloud {
		// hook template loading
		store.NotFoundCallback = func(template string) bool {
			parsed, parseErr := strconv.ParseInt(template, 10, 64)
			if parseErr != nil {
				if err := r.cloudClient.ExistsDataSourceItem(nucleicloud.ExistsDataSourceItemRequest{Type: "templates", Contents: template}); err == nil {
					cloudTemplates = append(cloudTemplates, template)
					return true
				}
				return false
			}
			if exists, err := r.cloudClient.ExistsTemplate(parsed); err == nil {
				cloudTemplates = append(cloudTemplates, exists.Reference)
				return true
			}
			return false
		}
	}
	if r.options.Validate {
		if err := store.ValidateTemplates(); err != nil {
			return err
		}
		if stats.GetValue(parsers.SyntaxErrorStats) == 0 && stats.GetValue(parsers.SyntaxWarningStats) == 0 && stats.GetValue(parsers.RuntimeWarningsStats) == 0 {
			gologger.Info().Msgf("All templates validated successfully\n")
		} else {
			return errors.New("encountered errors while performing template validation")
		}
		return nil // exit
	}
	store.Load()

	// add the hosts from the metadata queries of loaded templates into input provider
	if r.options.Uncover && len(r.options.UncoverQuery) == 0 {
		ret := uncover.GetUncoverTargetsFromMetadata(store.Templates(), r.options.UncoverDelay, r.options.UncoverLimit, r.options.UncoverField)
		for host := range ret {
			r.hmapInputProvider.Set(host)
		}
	}
	// list all templates
	if r.options.TemplateList || r.options.TemplateDisplay {
		r.listAvailableStoreTemplates(store)
		os.Exit(0)
	}
	r.displayExecutionInfo(store)

	// If not explicitly disabled, check if http based protocols
	// are used and if inputs are non-http to pre-perform probing
	// of urls and storing them for execution.
	if !r.options.DisableHTTPProbe && loader.IsHTTPBasedProtocolUsed(store) && r.isInputNonHTTP() {
		inputHelpers, err := r.initializeTemplatesHTTPInput()
		if err != nil {
			return errors.Wrap(err, "could not probe http input")
		}
		executerOpts.InputHelper.InputsHTTP = inputHelpers
	}

	enumeration := false
	var results *atomic.Bool
	if r.options.Cloud {
		if r.options.ScanList {
			err = r.getScanList(r.options.OutputLimit)
		} else if r.options.DeleteScan != "" {
			err = r.deleteScan(r.options.DeleteScan)
		} else if r.options.ScanOutput != "" {
			err = r.getResults(r.options.ScanOutput, r.options.OutputLimit)
		} else if r.options.ListDatasources {
			err = r.listDatasources()
		} else if r.options.ListTargets {
			err = r.listTargets()
		} else if r.options.ListTemplates {
			err = r.listTemplates()
		} else if r.options.AddDatasource != "" {
			err = r.addCloudDataSource(r.options.AddDatasource)
		} else if r.options.RemoveDatasource != "" {
			err = r.removeDatasource(r.options.RemoveDatasource)
		} else if r.options.AddTarget != "" {
			err = r.addTarget(r.options.AddTarget)
		} else if r.options.AddTemplate != "" {
			err = r.addTemplate(r.options.AddTemplate)
		} else if r.options.GetTarget != "" {
			err = r.getTarget(r.options.GetTarget)
		} else if r.options.GetTemplate != "" {
			err = r.getTemplate(r.options.GetTemplate)
		} else if r.options.RemoveTarget != "" {
			err = r.removeTarget(r.options.RemoveTarget)
		} else if r.options.RemoveTemplate != "" {
			err = r.removeTemplate(r.options.RemoveTemplate)
		} else {
			if len(store.Templates())+len(store.Workflows())+len(cloudTemplates) == 0 {
				return errors.New("no templates provided for scan")
			}
			gologger.Info().Msgf("Running scan on cloud with URL %s", r.options.CloudURL)
			results, err = r.runCloudEnumeration(store, cloudTemplates, r.cloudTargets, r.options.NoStore, r.options.OutputLimit)
			enumeration = true
		}
	} else {
		results, err = r.runStandardEnumeration(executerOpts, store, engine)
		enumeration = true
	}

	if !enumeration {
		return err
	}

	if r.interactsh != nil {
		matched := r.interactsh.Close()
		if matched {
			results.CompareAndSwap(false, true)
		}
	}
	r.progress.Stop()

	if executerOpts.InputHelper != nil {
		_ = executerOpts.InputHelper.Close()
	}
	if r.issuesClient != nil {
		r.issuesClient.Close()
	}

	if !results.Load() {
		gologger.Info().Msgf("No results found. Better luck next time!")
	}
	if r.browser != nil {
		r.browser.Close()
	}
	return err
}

func (r *Runner) isInputNonHTTP() bool {
	var nonURLInput bool
	r.hmapInputProvider.Scan(func(value *contextargs.MetaInput) bool {
		if !strings.Contains(value.Input, "://") {
			nonURLInput = true
			return false
		}
		return true
	})
	return nonURLInput
}

func (r *Runner) executeSmartWorkflowInput(executerOpts protocols.ExecuterOptions, store *loader.Store, engine *core.Engine) (*atomic.Bool, error) {
	r.progress.Init(r.hmapInputProvider.Count(), 0, 0)

	service, err := automaticscan.New(automaticscan.Options{
		ExecuterOpts: executerOpts,
		Store:        store,
		Engine:       engine,
		Target:       r.hmapInputProvider,
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not create automatic scan service")
	}
	service.Execute()
	result := &atomic.Bool{}
	result.Store(service.Close())
	return result, nil
}

func (r *Runner) executeTemplatesInput(store *loader.Store, engine *core.Engine) (*atomic.Bool, error) {
	var unclusteredRequests int64
	for _, template := range store.Templates() {
		// workflows will dynamically adjust the totals while running, as
		// it can't be known in advance which requests will be called
		if len(template.Workflows) > 0 {
			continue
		}
		unclusteredRequests += int64(template.TotalRequests) * r.hmapInputProvider.Count()
	}

	if r.options.VerboseVerbose {
		for _, template := range store.Templates() {
			r.logAvailableTemplate(template.Path)
		}
		for _, template := range store.Workflows() {
			r.logAvailableTemplate(template.Path)
		}
	}

	// Cluster the templates first because we want info on how many
	// templates did we cluster for showing to user in CLI
	originalTemplatesCount := len(store.Templates())
	finalTemplates, clusterCount := templates.ClusterTemplates(store.Templates(), engine.ExecuterOptions())
	finalTemplates = append(finalTemplates, store.Workflows()...)

	var totalRequests int64
	for _, t := range finalTemplates {
		if len(t.Workflows) > 0 {
			continue
		}
		totalRequests += int64(t.Executer.Requests()) * r.hmapInputProvider.Count()
	}
	if totalRequests < unclusteredRequests {
		gologger.Info().Msgf("Templates clustered: %d (Reduced %d HTTP Requests)", clusterCount, unclusteredRequests-totalRequests)
	}
	workflowCount := len(store.Workflows())
	templateCount := originalTemplatesCount + workflowCount

	// 0 matches means no templates were found in directory
	if templateCount == 0 {
		return &atomic.Bool{}, errors.New("no valid templates were found")
	}

	// tracks global progress and captures stdout/stderr until p.Wait finishes
	r.progress.Init(r.hmapInputProvider.Count(), templateCount, totalRequests)

	results := engine.ExecuteScanWithOpts(finalTemplates, r.hmapInputProvider, true)
	return results, nil
}

// displayExecutionInfo displays misc info about the nuclei engine execution
func (r *Runner) displayExecutionInfo(store *loader.Store) {
	// Display stats for any loaded templates' syntax warnings or errors
	stats.Display(parsers.SyntaxWarningStats)
	stats.Display(parsers.SyntaxErrorStats)
	stats.Display(parsers.RuntimeWarningsStats)

	builder := &strings.Builder{}
	if r.templatesConfig != nil && r.templatesConfig.NucleiLatestVersion != "" {
		builder.WriteString(" (")

		if strings.Contains(config.Version, "-dev") {
			builder.WriteString(r.colorizer.Blue("development").String())
		} else if config.Version == r.templatesConfig.NucleiLatestVersion {
			builder.WriteString(r.colorizer.Green("latest").String())
		} else {
			builder.WriteString(r.colorizer.Red("outdated").String())
		}
		builder.WriteString(")")
	}
	messageStr := builder.String()
	builder.Reset()

	gologger.Info().Msgf("Using Nuclei Engine %s%s", config.Version, messageStr)

	if r.templatesConfig != nil && r.templatesConfig.NucleiTemplatesLatestVersion != "" { // TODO extract duplicated logic
		builder.WriteString(" (")

		if r.templatesConfig.TemplateVersion == r.templatesConfig.NucleiTemplatesLatestVersion {
			builder.WriteString(r.colorizer.Green("latest").String())
		} else {
			builder.WriteString(r.colorizer.Red("outdated").String())
		}
		builder.WriteString(")")
	}
	messageStr = builder.String()
	builder.Reset()

	if r.templatesConfig != nil {
		gologger.Info().Msgf("Using Nuclei Templates %s%s", r.templatesConfig.TemplateVersion, messageStr)
	}
	if len(store.Templates()) > 0 {
		gologger.Info().Msgf("Templates added in last update: %d", r.countNewTemplates())
		gologger.Info().Msgf("Templates loaded for scan: %d", len(store.Templates()))
	}
	if len(store.Workflows()) > 0 {
		gologger.Info().Msgf("Workflows loaded for scan: %d", len(store.Workflows()))
	}
	if r.hmapInputProvider.Count() > 0 {
		gologger.Info().Msgf("Targets loaded for scan: %d", r.hmapInputProvider.Count())
	}
}

func (r *Runner) readNewTemplatesWithVersionFile(version string) ([]string, error) {
	resp, err := http.DefaultClient.Get(fmt.Sprintf("https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/%s/.new-additions", version))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("version not found")
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	templatesList := []string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}
		if isTemplate(text) {
			templatesList = append(templatesList, text)
		}
	}
	return templatesList, nil
}

// readNewTemplatesFile reads newly added templates from directory if it exists
func (r *Runner) readNewTemplatesFile() ([]string, error) {
	if r.templatesConfig == nil {
		return nil, nil
	}
	additionsFile := filepath.Join(r.templatesConfig.TemplatesDirectory, ".new-additions")
	file, err := os.Open(additionsFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	templatesList := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}
		if isTemplate(text) {
			templatesList = append(templatesList, text)
		}
	}
	return templatesList, nil
}

// countNewTemplates returns the number of newly added templates
func (r *Runner) countNewTemplates() int {
	if r.templatesConfig == nil {
		return 0
	}
	additionsFile := filepath.Join(r.templatesConfig.TemplatesDirectory, ".new-additions")
	file, err := os.Open(additionsFile)
	if err != nil {
		return 0
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}

		if isTemplate(text) {
			count++
		}

	}
	return count
}

func isTemplate(filename string) bool {
	return stringsutil.EqualFoldAny(filepath.Ext(filename), templates.TemplateExtension)
}

// SaveResumeConfig to file
func (r *Runner) SaveResumeConfig(path string) error {
	resumeCfgClone := r.resumeCfg.Clone()
	resumeCfgClone.ResumeFrom = resumeCfgClone.Current
	data, _ := json.MarshalIndent(resumeCfgClone, "", "\t")

	return os.WriteFile(path, data, os.ModePerm)
}
