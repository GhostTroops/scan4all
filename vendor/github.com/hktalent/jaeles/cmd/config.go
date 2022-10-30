package cmd

import (
	"fmt"
	"github.com/fatih/color"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/hktalent/jaeles/core"
	"github.com/hktalent/jaeles/database"
	"github.com/hktalent/jaeles/libs"
	"github.com/hktalent/jaeles/utils"
	"github.com/spf13/cobra"
)

func init() {
	var configCmd = &cobra.Command{
		Use:   "config",
		Short: "Configuration CLI",
		Long:  libs.Banner(),
		RunE:  runConfig,
	}
	configCmd.Flags().Bool("clean", false, "Clean old record")
	configCmd.Flags().StringP("action", "a", "", "Action")
	// used for cred action
	configCmd.Flags().Bool("poll", false, "Polling all record in OOB config")
	configCmd.Flags().String("secret", "", "Secret of Burp Collab")
	configCmd.Flags().String("collab", "", "List of Burp Collab File")
	// used for update action
	configCmd.Flags().BoolVar(&Options.Config.SkipMics, "mics", true, "Skip import mics signatures")
	configCmd.Flags().BoolVarP(&Options.Config.Forced, "yes", "y", false, "Forced to delete old folder")
	configCmd.Flags().StringVar(&Options.Config.Username, "user", "", "Username")
	configCmd.Flags().StringVar(&Options.Config.Password, "pass", "", "Password")
	configCmd.Flags().StringVar(&Options.Config.Repo, "repo", "", "Signature Repo")
	configCmd.Flags().StringVarP(&Options.Config.PrivateKey, "key", "K", "", "Private Key to pull repo")
	configCmd.SetHelpFunc(configHelp)
	RootCmd.AddCommand(configCmd)

}

func runConfig(cmd *cobra.Command, args []string) error {
	sort.Strings(args)
	// print more help
	helps, _ := cmd.Flags().GetBool("hh")
	if helps == true {
		HelpMessage()
		os.Exit(1)
	}
	// turn on verbose by default
	Options.Verbose = true
	polling, _ := cmd.Flags().GetBool("poll")
	// polling all oob
	if polling == true {
		secret, _ := cmd.Flags().GetString("secret")
		collabFile, _ := cmd.Flags().GetString("collab")
		collabs := utils.ReadingLines(collabFile)
		for _, collab := range collabs {
			database.ImportCollab(secret, collab)
		}
	}

	action, _ := cmd.Flags().GetString("action")
	// backward compatible
	if action == "" && len(args) > 0 {
		action = args[0]
	}
	getJaelesEnv(&Options)

	switch action {
	case "init":
		if Options.Config.Forced {
			os.RemoveAll(Options.SignFolder)
			core.UpdatePlugins(Options)
			core.UpdateSignature(Options)
		}
		reloadSignature(Options.SignFolder, Options.Config.SkipMics)
		break
	case "update":
		if Options.Config.Forced {
			os.RemoveAll(Options.SignFolder)
		} else {
			// only ask if use default Repo
			if utils.FolderExists(Options.SignFolder) && Options.Config.Repo == "" {
				mess := fmt.Sprintf("Looks like you already have signatures in %s\nDo you want to to override it?", Options.RootFolder)
				c := utils.PromptConfirm(mess)
				if c {
					utils.InforF("Cleaning root folder")
					os.RemoveAll(Options.SignFolder)
				}
			}
		}
		database.CleanSigns()
		core.UpdatePlugins(Options)
		core.UpdateSignature(Options)
		reloadSignature(path.Join(Options.RootFolder, "base-signatures"), Options.Config.SkipMics)
		break
	case "clear":
		utils.GoodF("Cleaning your DB")
		database.CleanScans()
		database.CleanSigns()
		database.CleanRecords()
		break
	case "clean":
		utils.InforF("Cleaning root folder: %v", Options.RootFolder)
		os.RemoveAll(Options.RootFolder)
		break
	case "cred":
		database.CreateUser(Options.Config.Username, Options.Config.Password)
		utils.GoodF("Create new credentials %v:%v \n", Options.Config.Username, Options.Config.Password)
		break
	case "oob":
		secret, _ := cmd.Flags().GetString("secret")
		collabFile, _ := cmd.Flags().GetString("collab")
		collabs := utils.ReadingLines(collabFile)
		for _, collab := range collabs {
			database.ImportCollab(secret, collab)
		}
		break
	case "reload":
		os.RemoveAll(path.Join(Options.RootFolder, "base-signatures"))
		InitDB()
		reloadSignature(Options.SignFolder, Options.Config.SkipMics)
		break
	case "add":
		addSignature(Options.SignFolder)
		break
	case "select":
		SelectSign()
		if len(Options.SelectedSigns) == 0 {
			fmt.Fprintf(os.Stderr, "[Error] No signature loaded\n")
			fmt.Fprintf(os.Stderr, "Use 'jaeles -h' for more information about a command.\n")
		} else {
			utils.GoodF("Signatures Loaded: %v", strings.Join(Options.SelectedSigns, " "))
		}
		break
	default:
		HelpMessage()
	}
	CleanOutput()
	return nil
}

// addSignature add active signatures from a folder
func addSignature(signFolder string) {
	signFolder = utils.NormalizePath(signFolder)
	if !utils.FolderExists(signFolder) {
		utils.ErrorF("Signature folder not found: %v", signFolder)
		return
	}
	allSigns := utils.GetFileNames(signFolder, ".yaml")
	if allSigns != nil {
		utils.InforF("Add Signature from: %v", signFolder)
		for _, signFile := range allSigns {
			database.ImportSign(signFile)
		}
	}
}

// reloadSignature signature
func reloadSignature(signFolder string, skipMics bool) {
	signFolder = utils.NormalizePath(signFolder)
	if !utils.FolderExists(signFolder) {
		utils.ErrorF("Signature folder not found: %v", signFolder)
		return
	}
	utils.GoodF("Reload signature in: %v", signFolder)
	database.CleanSigns()
	SignFolder, _ := filepath.Abs(path.Join(Options.RootFolder, "base-signatures"))
	if signFolder != "" && utils.FolderExists(signFolder) {
		SignFolder = signFolder
	}
	allSigns := utils.GetFileNames(SignFolder, ".yaml")
	if len(allSigns) > 0 {
		utils.InforF("Load Signature from: %v", SignFolder)
		for _, signFile := range allSigns {
			if skipMics {
				if strings.Contains(signFile, "/mics/") {
					utils.DebugF("Skip sign: %v", signFile)
					continue
				}

				if strings.Contains(signFile, "/exper/") {
					utils.DebugF("Skip sign: %v", signFile)
					continue
				}
			}
			utils.DebugF("Importing signature: %v", signFile)
			err := database.ImportSign(signFile)
			if err != nil {
				utils.ErrorF("Error importing signature: %v", signFile)
			}
		}
	}

	signPath := path.Join(Options.RootFolder, "base-signatures")
	passivePath := path.Join(signPath, "passives")
	resourcesPath := path.Join(signPath, "resources")
	thirdpartyPath := path.Join(signPath, "thirdparty")

	// copy it to base signature folder
	if !utils.FolderExists(signPath) {
		utils.CopyDir(signFolder, signPath)
	}

	// move passive signatures to default passive
	if utils.FolderExists(passivePath) {
		utils.MoveFolder(passivePath, Options.PassiveFolder)
	}
	if utils.FolderExists(resourcesPath) {
		utils.MoveFolder(resourcesPath, Options.ResourcesFolder)
	}
	if utils.FolderExists(thirdpartyPath) {
		utils.MoveFolder(thirdpartyPath, Options.ThirdPartyFolder)
	}

}

func configHelp(_ *cobra.Command, _ []string) {
	fmt.Println(libs.Banner())
	HelpMessage()
}

func rootHelp(cmd *cobra.Command, _ []string) {
	fmt.Println(libs.Banner())
	helps, _ := cmd.Flags().GetBool("hh")
	if helps {
		fmt.Println(cmd.UsageString())
		return
	}
	RootMessage()
}

// RootMessage print help message
func RootMessage() {
	h := "\nUsage:\n jaeles scan|server|config [Options]\n"
	h += " jaeles scan|server|config|report -h -- Show usage message\n"
	h += "\nSubcommands:\n"
	h += "  jaeles scan   --  Scan list of URLs based on selected signatures\n"
	h += "  jaeles server --  Start API server\n"
	h += "  jaeles config --  Configuration CLI \n"
	h += "  jaeles report --  Generate HTML report based on scanned output \n"
	h += `
Core Flags:
  -c, --concurrency int         Set the concurrency level (default 20)
  -o, --output string           Output folder name (default "out")
  -s, --signs strings           Signature selector (Multiple -s flags are accepted)
  -x, --exclude strings         Exclude Signature selector (Multiple -x flags are accepted)
  -L, --level int               Filter signatures by level (default 1)
  -G, --passive                 Turn on passive detections (default: false)
  -p, --params strings          Custom params -p='foo=bar' (Multiple -p flags are accepted)
  -H, --headers strings         Custom headers (e.g: -H 'Referer: {{.BaseURL}}') (Multiple -H flags are accepted)

Mics Flags:
      --hh string               Full help message
  -v, --verbose                 Verbose output
      --debug                   Enable Debug mode
      --proxy string            Proxy for sending request
      --timeout int             HTTP timeout (default 20s)
      --no-db                   Disable Database
  -S, --selectorFile string     Signature selector from file
  -J, --format-input            Enable special input format (default is false)
  -f, --found string            Run host OS command when vulnerable found
  -O, --summaryOutput string    Summary output file (default is "jaeles-summary.txt")
      --passiveOutput string    Passive output folder (default is "passive-out")
      --passiveSummary string   Passive Summary file
      --sp string               Selector for passive detections (default "*")
      --single string           Forced running in single mode
      --sverbose bool           Store verbose info in summary file
  -N  --no-output bool          Disable store output
      --chunk bool              Enable chunk running against big input
  -I, --inline string           Inline Detections
  -q, --quiet                   Enable Quiet Output
  -Q, --quietFormat string      Format for quiet output (default "{{.VulnURL}}")
  -R, --report string           HTML report file name
      --title string            HTML report title
      --html string             Enable generate HTML reports after the scan done 
      --json bool               Store output as JSON format
      --local                   Enable local analyze (Accept input as local path e.g: -u /tmp/req.txt)
      --dr                      Shortcut for disable replicate request (avoid sending many timeout requests)
      --fi                      Enable filtering mode (to use Diff() detection)
      --lc                      Shortcut for '--proxy http://127.0.0.1:8080'
      --at                      Enable Always True Detection for observe response
      --ba                      Shortcut for take raw input as '{{.BaseURL}}'
`
	h += "\n\nExamples Commands:\n"
	h += "  jaeles scan -s <signature> -u <url>\n"
	h += "  jaeles scan -c 50 -s <signature> -U <list_urls> -L <level-of-signatures>\n"
	h += "  jaeles scan -c 50 -s <signature> -U <list_urls>\n"
	h += "  jaeles scan --fi -c 50 -s <sensitive-signature> -U <list_urls>\n"
	h += "  jaeles scan --local -s <local-analyze> -u /path/to/response-file.txt\n"
	h += "  jaeles scan -c 50 -s <signature> -U <list_urls> -p 'dest=xxx.burpcollaborator.net'\n"
	h += "  jaeles scan -c 50 -s <signature> -U <list_urls> -f 'noti_slack \"{{.vulnInfo}}\"'\n"
	h += "  jaeles scan -v -c 50 -s <signature> -U list_target.txt -o /tmp/output\n"
	h += "  jaeles scan -s <signature> -s <another-selector> -u http://example.com\n"
	h += "  echo '{\"BaseURL\":\"https://example.com/sub/\"}' | jaeles scan -s sign.yaml -J \n"
	h += "  jaeles scan -G -s <signature> -s <another-selector> -x <exclude-selector> -u http://example.com\n"
	h += "  cat list_target.txt | jaeles scan -c 100 -s <signature>\n"

	h += "\nOthers Commands:\n"
	h += "  jaeles server -s '/tmp/custom-signature/sensitive/.*' -L 2 --fi\n"
	h += "  jaeles server --host 0.0.0.0 --port 5000 -s '/tmp/custom-signature/sensitive/.*' -L 2\n"
	h += "  jaeles config reload --signDir /tmp/standard-signatures/\n"
	h += "  jaeles config add -B /tmp/custom-active-signatures/\n"
	h += "  jaeles config update --repo https://github.com/hktalent/jaeles-signatures\n"
	h += "  jaeles report -o /tmp/scanned/out\n"
	h += "  jaeles report -o /tmp/scanned/out --title 'Passive Report'\n"
	h += "  jaeles report -o /tmp/scanned/out --title 'Verbose Report' --sverbose\n"
	fmt.Println(h)
	fmt.Printf("Official Documentation can be found here: %s\n", color.GreenString(libs.DOCS))

}

// HelpMessage print help message
func HelpMessage() {
	h := `
Usage:
  jaeles config [action]

Config Command examples:
  # Init default signatures
  jaeles config init

  # Update latest signatures
  jaeles config update
  jaeles config update --repo http://github.com/jaeles-project/another-signatures --user admin --pass admin
  jaeles config update --repo git@github.com/jaeles-project/another-signatures -K your_private_key

  # Reload signatures from a standard signatures folder (contain passives + resources)
  jaeles config reload --signDir ~/standard-signatures/
  
  # Add custom signatures from folder
  jaeles config add --signDir ~/custom-signatures/

  # Clean old stuff
  jaeles config clean

  # More examples
  jaeles config add --signDir /tmp/standard-signatures/
  jaeles config cred --user sample --pass not123456
	`
	fmt.Println(h)
	fmt.Printf("Official Documentation can be found here: %s\n", color.GreenString(libs.DOCS))

}

func ScanHelp(cmd *cobra.Command, _ []string) {
	fmt.Println(libs.Banner())
	fmt.Println(cmd.UsageString())
	ScanMessage()
}

// ScanMessage print help message
func ScanMessage() {
	h := "\nScan Usage example:\n"
	h += "  jaeles scan -s <signature> -u <url>\n"
	h += "  jaeles scan -c 50 -s <signature> -U <list_urls> -L <level-of-signatures>\n"
	h += "  jaeles scan -c 50 -s <signature> -U <list_urls>\n"
	h += "  jaeles scan --fi -c 50 -s <sensitive-signature> -U <list_urls>\n"
	h += "  jaeles scan --local -s <local-analyze> -u /path/to/response-file.txt\n"
	h += "  jaeles scan -c 50 -s <signature> -U <list_urls> -p 'dest=xxx.burpcollaborator.net'\n"
	h += "  jaeles scan -c 50 -s <signature> -U <list_urls> -f 'noti_slack \"{{.vulnInfo}}\"'\n"
	h += "  jaeles scan -v -c 50 -s <signature> -U list_target.txt -o /tmp/output\n"
	h += "  jaeles scan -s <signature> -s <another-selector> -u http://example.com\n"
	h += "  echo '{\"BaseURL\":\"https://example.com/sub/\"}' | jaeles scan -s sign.yaml -J \n"
	h += "  jaeles scan -G -s <signature> -s <another-selector> -x <exclude-selector> -u http://example.com\n"
	h += "  cat list_target.txt | jaeles scan -c 100 -s <signature>\n"

	h += "\n\nExamples:\n"
	h += "  jaeles scan -s 'jira' -s 'ruby' -u target.com\n"
	h += "  jaeles scan -c 50 -s 'java' -x 'tomcat' -U list_of_urls.txt\n"
	h += "  jaeles scan -G -c 50 -s '/tmp/custom-signature/.*' -U list_of_urls.txt\n"
	h += "  jaeles scan -v -s '~/my-signatures/products/wordpress/.*' -u 'https://wp.example.com' -p 'root=[[.URL]]'\n"
	h += "  cat urls.txt | grep 'interesting' | jaeles scan -L 5 -c 50 -s 'fuzz/.*' -U list_of_urls.txt --proxy http://127.0.0.1:8080\n"
	h += "\n"
	fmt.Println(h)
	fmt.Printf("Official Documentation can be found here: %s\n", color.GreenString(libs.DOCS))
}

// ServerHelp report help message
func ServerHelp(cmd *cobra.Command, _ []string) {
	fmt.Println(libs.Banner())
	fmt.Println(cmd.UsageString())
	fmt.Printf("Official Documentation can be found here: %s\n", color.GreenString(libs.DOCS))

}

// ReportHelp report help message
func ReportHelp(cmd *cobra.Command, _ []string) {
	fmt.Println(libs.Banner())
	fmt.Println(cmd.UsageString())
	fmt.Printf("Official Documentation can be found here: %s\n", color.GreenString(libs.DOCS))
}

func getJaelesEnv(options *libs.Options) {
	if utils.GetOSEnv("JAELES_REPO") != "JAELES_REPO" {
		options.Config.Repo = utils.GetOSEnv("JAELES_REPO")
	}
	if utils.GetOSEnv("JAELES_KEY") != "JAELES_KEY" {
		options.Config.PrivateKey = utils.GetOSEnv("JAELES_KEY")
	}
}

// CleanOutput clean the output folder in case nothing found
func CleanOutput() {
	// clean output
	if utils.DirLength(Options.Output) == 0 {
		os.RemoveAll(Options.Output)
	}
	if utils.DirLength(Options.PassiveFolder) == 0 {
		os.RemoveAll(Options.PassiveFolder)
	}

	// unique vulnSummary
	// Sort sort content of a file
	data := utils.ReadingFileUnique(Options.SummaryVuln)
	if len(data) == 0 {
		return
	}
	sort.Strings(data)
	content := strings.Join(data, "\n")
	// remove blank line
	content = regexp.MustCompile(`[\t\r\n]+`).ReplaceAllString(strings.TrimSpace(content), "\n")
	utils.WriteToFile(Options.SummaryVuln, content)
}
