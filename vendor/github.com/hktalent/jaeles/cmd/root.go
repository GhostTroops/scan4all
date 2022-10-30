package cmd

import (
	"fmt"
	"github.com/fatih/color"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hktalent/jaeles/core"
	"github.com/hktalent/jaeles/database"
	"github.com/hktalent/jaeles/libs"
	"github.com/hktalent/jaeles/utils"
	"github.com/jinzhu/gorm"
	"github.com/spf13/cobra"
	"github.com/thoas/go-funk"
)

var Options = libs.Options{}

// DB database variables
var _ *gorm.DB

var RootCmd = &cobra.Command{
	Use:   "jaeles",
	Short: "Jaeles Scanner",
	Long:  libs.Banner(),
}

// Execute main function
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	// config Options
	RootCmd.PersistentFlags().StringVar(&Options.ConfigFile, "config", "", "config file (default is $HOME/.jaeles/config.yaml)")
	RootCmd.PersistentFlags().StringVar(&Options.RootFolder, "rootDir", "~/.jaeles/", "root Project")
	RootCmd.PersistentFlags().StringVarP(&Options.SignFolder, "signDir", "B", "~/.jaeles/base-signatures/", "Folder contain default signatures")
	RootCmd.PersistentFlags().StringVar(&Options.ScanID, "scanID", "", "Scan ID")
	// http Options
	RootCmd.PersistentFlags().StringVar(&Options.Proxy, "proxy", "", "proxy")
	RootCmd.PersistentFlags().IntVar(&Options.Timeout, "timeout", 20, "HTTP timeout")
	RootCmd.PersistentFlags().IntVar(&Options.Retry, "retry", 0, "HTTP Retry")
	RootCmd.PersistentFlags().IntVar(&Options.Delay, "delay", 0, "Delay time between requests")
	// output Options
	RootCmd.PersistentFlags().StringVarP(&Options.Output, "output", "o", "out", "Output folder name")
	RootCmd.PersistentFlags().BoolVar(&Options.JsonOutput, "json", false, "Store output as JSON")
	RootCmd.PersistentFlags().StringVar(&Options.PassiveOutput, "passiveOutput", "", "Passive output folder (default is passive-out)")
	RootCmd.PersistentFlags().StringVar(&Options.PassiveSummary, "passiveSummary", "", "Passive Summary file")
	RootCmd.PersistentFlags().StringVarP(&Options.SummaryOutput, "summaryOutput", "O", "", "Summary output file")
	RootCmd.PersistentFlags().StringVar(&Options.SummaryVuln, "summaryVuln", "", "Summary output file")
	RootCmd.PersistentFlags().BoolVar(&Options.VerboseSummary, "sverbose", false, "Store verbose info in summary file")
	// report Options
	RootCmd.PersistentFlags().StringVarP(&Options.Report.ReportName, "report", "R", "", "Report name")
	RootCmd.PersistentFlags().StringVar(&Options.Report.Title, "title", "", "Report title name")
	// core Options
	RootCmd.PersistentFlags().BoolVarP(&Options.EnablePassive, "passive", "G", false, "Turn on passive detections")
	RootCmd.PersistentFlags().IntVarP(&Options.Level, "level", "L", 1, "Filter signature by level")
	RootCmd.PersistentFlags().StringVar(&Options.SelectedPassive, "sp", "*", "Selector for passive detections")
	RootCmd.PersistentFlags().IntVarP(&Options.Concurrency, "concurrency", "c", 20, "Set the concurrency level")
	RootCmd.PersistentFlags().IntVarP(&Options.Threads, "threads", "t", 10, "Set the concurrency level inside single signature")
	RootCmd.PersistentFlags().StringVarP(&Options.Selectors, "selectorFile", "S", "", "Signature selector from file")
	RootCmd.PersistentFlags().StringSliceVarP(&Options.Signs, "signs", "s", []string{}, "Signature selector (Multiple -s flags are accepted)")
	RootCmd.PersistentFlags().StringSliceVarP(&Options.Excludes, "exclude", "x", []string{}, "Exclude Signature selector (Multiple -x flags are accepted)")
	RootCmd.PersistentFlags().BoolVar(&Options.LocalAnalyze, "local", false, "Enable local analyze (Accept input as local path)")
	// custom params from cli
	RootCmd.PersistentFlags().StringSliceVarP(&Options.Params, "params", "p", []string{}, "Custom params -p='foo=bar' (Multiple -p flags are accepted)")
	RootCmd.PersistentFlags().StringSliceVarP(&Options.Headers, "headers", "H", []string{}, "Custom headers (e.g: -H 'Referer: {{.BaseURL}}') (Multiple -H flags are accepted)")
	// misc Options
	RootCmd.PersistentFlags().StringVarP(&Options.LogFile, "log", "l", "", "log file")
	RootCmd.PersistentFlags().StringVarP(&Options.FoundCmd, "found", "f", "", "Run host OS command when vulnerable found")
	RootCmd.PersistentFlags().BoolVarP(&Options.EnableFormatInput, "format-input", "J", false, "Enable special input format")
	RootCmd.PersistentFlags().BoolVar(&Options.SaveRaw, "save-raw", false, "save raw request")
	RootCmd.PersistentFlags().BoolVarP(&Options.NoOutput, "no-output", "N", false, "Do not store output")
	RootCmd.PersistentFlags().BoolVar(&Options.NoBackGround, "no-background", true, "Do not run background task")
	RootCmd.PersistentFlags().IntVar(&Options.Refresh, "refresh", 10, "Refresh time for background task")
	RootCmd.PersistentFlags().BoolVar(&Options.NoDB, "no-db", false, "Disable Database")
	RootCmd.PersistentFlags().BoolVar(&Options.DisableParallel, "single", false, "Disable parallel mode (use this when you need logic in single signature")
	RootCmd.PersistentFlags().StringVarP(&Options.QuietFormat, "quietFormat", "Q", "{{.VulnURL}}", "Format for quiet output")
	RootCmd.PersistentFlags().BoolVarP(&Options.Quiet, "quiet", "q", false, "Quiet Output")
	RootCmd.PersistentFlags().BoolVarP(&Options.Verbose, "verbose", "v", false, "Verbose output")
	RootCmd.PersistentFlags().BoolVarP(&Options.Version, "version", "V", false, "Print version of Jaeles")
	RootCmd.PersistentFlags().BoolVar(&Options.Debug, "debug", false, "Debug")
	// chunk Options
	RootCmd.PersistentFlags().BoolVar(&Options.ChunkRun, "chunk", false, "Enable chunk running against big input")
	RootCmd.PersistentFlags().IntVar(&Options.ChunkThreads, "chunk-threads", 2, "Number of Chunk Threads")
	RootCmd.PersistentFlags().IntVar(&Options.ChunkSize, "chunk-size", 20000, "Chunk Size")
	RootCmd.PersistentFlags().StringVar(&Options.ChunkDir, "chunk-dir", "", "Temp Directory to store chunk directory")
	RootCmd.PersistentFlags().IntVar(&Options.ChunkLimit, "chunk-limit", 200000, "Limit size to trigger chunk run")
	// some shortcuts
	RootCmd.PersistentFlags().StringVarP(&Options.InlineDetection, "inline", "I", "", "Inline Detections")
	RootCmd.PersistentFlags().BoolVar(&Options.EnableFiltering, "fi", false, "Enable filtering mode (to use Diff() detection)")
	RootCmd.PersistentFlags().BoolVar(&Options.Mics.DisableReplicate, "dr", false, "Shortcut for disable replicate request (avoid sending many request to timeout)")
	RootCmd.PersistentFlags().BoolVar(&Options.Mics.BaseRoot, "ba", false, "Shortcut for take raw input as {{.BaseURL}}'")
	RootCmd.PersistentFlags().BoolVar(&Options.Mics.BurpProxy, "lc", false, "Shortcut for '--proxy http://127.0.0.1:8080'")
	RootCmd.PersistentFlags().BoolVar(&Options.Mics.AlwaysTrue, "at", false, "Enable Always True Detection for observe response")
	RootCmd.PersistentFlags().BoolVar(&Options.Mics.FullHelp, "hh", false, "Show full help message")
	RootCmd.SetHelpFunc(rootHelp)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	// set some mics info
	fmt.Fprintf(os.Stderr, "Jaeles %v by %v\n", libs.VERSION, libs.AUTHOR)
	if Options.Version {
		os.Exit(0)
	}
	if Options.Debug {
		Options.Verbose = true
	}
	// some shortcut
	if Options.Mics.BurpProxy {
		Options.Proxy = "http://127.0.0.1:8080"
	}

	if Options.Mics.AlwaysTrue {
		Options.NoOutput = true
	}

	utils.InitLog(&Options)
	core.InitConfig(&Options)
	InitDB()
}

func InitDB() {
	var err error
	if !Options.NoDB {
		_, err = database.InitDB(utils.NormalizePath(Options.Server.DBPath))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Can't connect to DB at %v\n", Options.Server.DBPath)
			fmt.Fprintf(os.Stderr, "Use '--no-db' for to disable DB connection if you want.\n")
			fmt.Fprintf(os.Stderr, "[Tips] run 'rm -rf ~/.jaeles/' and run 'jaeles config init' to reload the DB\n")
			os.Exit(-1)
		}
	}
}

// SelectSign select signature
func SelectSign() {
	var selectedSigns []string
	// read selector from File
	if Options.Selectors != "" {
		Options.Signs = append(Options.Signs, utils.ReadingFileUnique(Options.Selectors)...)
	}

	// default is all signature
	if len(Options.Signs) == 0 {
		selectedSigns = core.SelectSign("**")
	}

	// search signature through Signatures table
	for _, signName := range Options.Signs {
		selectedSigns = append(selectedSigns, core.SelectSign(signName)...)
		if !Options.NoDB {
			Signs := database.SelectSign(signName)
			selectedSigns = append(selectedSigns, Signs...)
		}
	}

	// exclude some signature
	if len(Options.Excludes) > 0 {
		for _, exclude := range Options.Excludes {
			for index, sign := range selectedSigns {
				if strings.Contains(sign, exclude) {
					selectedSigns = append(selectedSigns[:index], selectedSigns[index+1:]...)
				}
				r, err := regexp.Compile(exclude)
				if err != nil {
					continue
				}
				if r.MatchString(sign) {
					selectedSigns = append(selectedSigns[:index], selectedSigns[index+1:]...)
				}
			}
		}
	}
	Options.SelectedSigns = selectedSigns

	if len(selectedSigns) == 0 {
		fmt.Fprintf(os.Stderr, "[Error] No signature loaded\n")
		fmt.Fprintf(os.Stderr, "Try '%s' to init default signatures\n", color.GreenString("jaeles config init"))
		os.Exit(1)
	}
	selectedSigns = funk.UniqString(selectedSigns)
	utils.InforF("Signatures Loaded: %v", len(selectedSigns))
	signInfo := fmt.Sprintf("Signature Loaded: ")
	for _, signName := range selectedSigns {
		signInfo += fmt.Sprintf("%v ", filepath.Base(signName))
	}
	utils.InforF(signInfo)

	// create new scan or group with old one
	var scanID string
	if Options.ScanID == "" {
		scanID = database.NewScan(Options, "scan", selectedSigns)
	} else {
		scanID = Options.ScanID
	}
	utils.InforF("Start Scan with ID: %v", scanID)
	Options.ScanID = scanID

	// only parse signature once to avoid I/O limit
	for _, signFile := range Options.SelectedSigns {
		sign, err := core.ParseSign(signFile)
		if err != nil {
			utils.ErrorF("Error parsing YAML sign: %v", signFile)
			continue
		}
		Options.ParsedSelectedSigns = append(Options.ParsedSelectedSigns, sign)
	}
}
