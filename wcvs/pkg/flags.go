package pkg

import (
	"fmt"
	"log"
	"runtime"
	"strings"
	"text/tabwriter"

	"golang.org/x/time/rate"
)

var (
	version   string
	useragent string

	generalOptions  []FlagStruct
	generateOptions []FlagStruct
	requestOptions  []FlagStruct
	crawlOptions    []FlagStruct
	wordlistOptions []FlagStruct
)

type FlagStruct struct {
	LongFlag    string
	ShortFlag   string
	Description string
}

const UserAgent = "51pwn_scan4all"

func init() {

}

func ParseFlags(vers, urlStr string) {
	/* Getting Command-line flags */
	version = vers
	useragent = UserAgent + " v" + version
	pathPrefix := ""
	if runtime.GOOS == "windows" {
		pathPrefix = "C:"
	}

	// General Options
	techniqueNames := "cookies,css,forwarding,smuggling,dos,headers,parameters,fatget,cloaking,splitting"

	appendInt(&generalOptions, &Config.Verbosity,
		"verbosity", "v", 1, "Set verbosity. 0 = quiet, 1 = normal, 2 = verbose")
	appendFloat(&generalOptions, &Config.ReqRate,
		"reqrate", "rr", float64(rate.Inf), "Requests per second. Float value. Has to be greater than 0. Default value is infinite")
	appendInt(&generalOptions, &Config.Threads,
		"threads", "t", 20, "Threads to use. Default value is 20")
	appendInt(&generalOptions, &Config.TimeOut,
		"timeout", "to", 15, "Seconds until timeout. Default value is 15")
	appendString(&generalOptions, &Config.OnlyTest,
		"onlytest", "ot", "", "Choose which tests to run. Use the , seperator to specify multiple ones. Example: -onlytest '"+techniqueNames+"'")
	appendString(&generalOptions, &Config.SkipTest,
		"skiptest", "st", "", "Choose which tests to not run. Use the , seperator to specify multiple ones. Example: -skiptest '"+techniqueNames+"'")
	appendString(&generalOptions, &Config.ProxyCertPath,
		"proxycertpath", "ppath", "", "Path to the cert of the proxy you want to use. The cert has to have the PEM Format. Burp e.g. is in the DER Format. Use the following command to convert it: openssl x509 -inform DER -outform PEM -text -in cacert.der -out certificate.pem")
	appendString(&generalOptions, &Config.ProxyURL,
		"proxyurl", "purl", "http://127.0.0.1:8080", "Url for the proxy. Default value is http://127.0.0.1:8080")
	appendBoolean(&generalOptions, &Config.Force,
		"force", "f", false, "Perform the tests no matter if there is a cache or even the cachebuster works or not")
	appendInt(&generalOptions, &Config.CLDiff,
		"contentlengthdifference", "cldiff", 0, "Threshold for reporting possible Finding, when 'poisoned' response differs more from the original length. Default is 0 (don't check)")
	appendInt(&generalOptions, &Config.HMDiff,
		"hitmissdifference", "hmdiff", 30, "Threshold for time difference between cache hit and cache miss responses. Default is 30")

	// Generate Options
	appendString(&generateOptions, &Config.GeneratePath,
		"generatepath", "gp", "./", "Path all files (log, report, completed) will be written to. Example: -gp '"+pathPrefix+"/p/a/t/h/'. Default is './'")
	appendBoolean(&generateOptions, &Config.GenerateReport,
		"generatereport", "gr", false, "Do you want a report to be generated?")
	appendBoolean(&generateOptions, &Config.EscapeJSON,
		"escapejson", "ej", false, "Do you want HTML special chars to be encoded in the report?")
	appendBoolean(&generateOptions, &Config.GenerateCompleted,
		"generatecompleted", "gc", false, "Do you want a list with completed URLs to be generated?")

	// Request Options
	var (
		setCookiesStr    string
		setHeadersStr    string
		setParametersStr string
		setBodyStr       string
		userAgentChrome  bool
	)

	appendBoolean(&requestOptions, &Config.UseHTTP,
		"usehttp", "http", false, "Use http instead of https for URLs, which doesn't specify either one")
	appendBoolean(&requestOptions, &Config.DeclineCookies,
		"declineCookies", "dc", false, "Do you don't want to use cookies, which are received in the response of the first request?")
	appendString(&requestOptions, &Config.CacheBuster,
		"cachebuster", "cb", "cb", "Specify the cachebuster to use. The default value is cachebuster")
	appendString(&requestOptions, &setCookiesStr,
		"setcookies", "sc", "", "Set a Cookie. Otherwise use file: to specify a file with urls. E.g. -sc uid=123 or -sc file:templates/cookie_list")
	appendString(&requestOptions, &setHeadersStr,
		"setheaders", "sh", "", "Set a Header. Otherwise use file: to specify a file with urls. E.g. -sh 'User-Agent: Safari/1.1' or -sh file:templates/header_list")
	appendString(&requestOptions, &setParametersStr,
		"setparameters", "sp", "", "Set a Query Parameter. Otherwise use file: to specify a file with urls. E.g. -sp user=admin or -sp file:templates/parameter_list")
	appendString(&requestOptions, &setBodyStr,
		"setbody", "sb", "", "Set the requests' body. Otherwise use file: to specify a file with urls. E.g. -sb 'admin=true' or -sh file:templates/body_file")
	appendBoolean(&requestOptions, &Config.DoPost,
		"post", "post", false, "Do a POST request instead of a GET request")
	appendString(&requestOptions, &Config.ContentType,
		"contenttype", "ct", "application/x-www-form-urlencoded", "Set the contenttype for a POST Request. Default is application/x-www-form-urlencoded. If you don't want a content-type to be used at all use -ct ''")
	appendString(&requestOptions, &Config.QuerySeperator,
		"parameterseperator", "ps", "&", "Specify the seperator for parameters. The default value is &")
	appendBoolean(&requestOptions, &userAgentChrome,
		"useragentchrome", "uac", false, "Set chrome as User-Agent. Default is "+UserAgent+" v{Version-Number}")

	// Crawl Options
	var (
		recExcludeStr string
		recDomainsStr string
	)

	appendInt(&crawlOptions, &Config.Recursivity,
		"recursivity", "r", 0, "Put (via href or src specified) urls at the end of the queue if the domain is the same. Specify how deep the recursivity shall go. Default value is 0 (no recursivity)")
	appendInt(&crawlOptions, &Config.RecLimit,
		"reclimit", "rl", 0, "Define a limit, how many files shall be checked recursively. Default is 0 (unlimited)")
	appendString(&crawlOptions, &Config.RecInclude,
		"recinclude", "rin", "", "Choose which links should be included. Seperate with a space. E.g: -rin '.js .css'")
	appendString(&crawlOptions, &recExcludeStr,
		"recexclude", "rex", "", "Use -cp (-completedpath) or -gc (-generatecompleted) to generate a list of already completed URLs. Use -rex path/to/file so the already completed URLs won't be tested again recursively.")
	appendString(&crawlOptions, &recDomainsStr,
		"recdomains", "red", "", "Define an additional domain which is allowed to be added recursively. Otherwise use file: to specify a file with urls. E.g. -sh 'api.example.com' or -sh file:templates/recdomains_list")

	// Wordlist Options
	appendString(&wordlistOptions, &Config.HeaderWordlist,
		"headerwordlist", "hw", "config/wordlists/headers", "Wordlist for headers to test. Default path is 'wordlists/top-headers'")
	appendString(&wordlistOptions, &Config.QueryWordlist,
		"parameterwordlist", "pw", "config/wordlists/parameters", "Wordlist for query parameters to test. Default path is 'wordlists/top-parameters'")

	//flag.CommandLine.Usage = help

	// flags need to be parsed, before they are used
	//flag.Parse()
	log.Printf("%+v", Config)
	//
	//if urlStr == "" {
	//	msg := "No url specified. Use -url or -u. Use -h or --help to get a list of all supported flags\n"
	//	PrintFatal(msg)
	//}

	// Change User Agent
	if userAgentChrome {
		useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36"
	}

	// Read RecExcludeURL(s)
	if recExcludeStr != "" {
		Config.RecExclude = ReadLocalFile(recExcludeStr, "RecExclude")
	}

	// Read RecDomain(s)
	Config.RecDomains = readFile(recDomainsStr, Config.RecDomains, "RecDomain")

	// Read URL(s)
	Config.Urls = readFile(urlStr, Config.Urls, "URL")

	// Read Cookie(s)
	Config.Cookies = readFile(setCookiesStr, Config.Cookies, "Cookie")

	// Read Header(s)
	Config.Headers = readFile(setHeadersStr, Config.Headers, "Heades")

	// Read Parameter(s)
	Config.Parameters = readFile(setParametersStr, Config.Parameters, "Parameter")

	/* Read Body */
	if strings.HasPrefix(setBodyStr, "path:") {
		bodySlice := ReadLocalFile(setBodyStr, "Body")
		for _, l := range bodySlice {
			l = strings.TrimSuffix(l, "\r")
			l = strings.TrimSpace(l)
			if strings.HasPrefix(l, "//") || l == "" {
				continue
			}
			Config.Body += l
		}
	} else {
		Config.Body = setBodyStr
	}

	// Set Limiter
	Config.Limiter = rate.NewLimiter(rate.Limit(Config.ReqRate), 1)

	Config.OnlyTest = strings.ToLower(Config.OnlyTest)
	Config.SkipTest = strings.ToLower(Config.SkipTest)
}

// TODO: is field []string needed here?
func readFile(str string, field []string, name string) []string {
	if strings.HasPrefix(str, "file:") {
		return ReadLocalFile(str, name)
	} else {
		return append(field, str)
	}
}

//
//func help() {
//	w := new(tabwriter.Writer)
//	w.Init(os.Stdout, 8, 8, 0, '\t', 0)
//
//	fmt.Println("Published by Hackmanit under http://www.apache.org/licenses/LICENSE-2.0")
//	fmt.Println("Author: Maximilian Hildebrand")
//	fmt.Println("Repository: https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner")
//	fmt.Println("Blog Post: https://hackmanit.de/en/blog-en/145-web-cache-vulnerability-scanner-wcvs-free-customizable-easy-to-use")
//	fmt.Printf("Version: %s\n\n", version)
//	fmt.Print("Usage: Web-Cache-Vulnerability-Scanner(.exe) [options]\n\n")
//
//	fmt.Println("General Options:")
//	fmt.Fprintf(w, "%s\t%s\t%s\n", "--help", "-h", "Show this help and quit")
//	writeToWriter(w, generalOptions)
//
//	fmt.Println("\nGenerate Options:")
//	writeToWriter(w, generateOptions)
//
//	fmt.Println("\nRequest Options:")
//	writeToWriter(w, requestOptions)
//
//	fmt.Println("\nCrawl Options:")
//	writeToWriter(w, crawlOptions)
//
//	fmt.Println("\nWordlist Options:")
//	writeToWriter(w, wordlistOptions)
//
//	os.Exit(0)
//}

func writeToWriter(w *tabwriter.Writer, flagStruct []FlagStruct) {
	for _, ts := range flagStruct {
		fmt.Fprintf(w, "--%s\t-%s\t%s\n", ts.LongFlag, ts.ShortFlag, ts.Description)
	}
	w.Flush()
}

func appendString(options *[]FlagStruct, varString *string, longFlag string, shortFlag string, defaultValue string, description string) {
	varString = &defaultValue
	*options = append(*options, FlagStruct{
		LongFlag:    longFlag,
		ShortFlag:   shortFlag,
		Description: description})
}

func appendInt(options *[]FlagStruct, varInt *int, longFlag string, shortFlag string, defaultValue int, description string) {
	varInt = &defaultValue
	*options = append(*options, FlagStruct{
		LongFlag:    longFlag,
		ShortFlag:   shortFlag,
		Description: description})
}

func appendFloat(options *[]FlagStruct, varFloat *float64, longFlag string, shortFlag string, defaultValue float64, description string) {
	varFloat = &defaultValue
	*options = append(*options, FlagStruct{
		LongFlag:    longFlag,
		ShortFlag:   shortFlag,
		Description: description})
}

func appendBoolean(options *[]FlagStruct, varBoolean *bool, longFlag string, shortFlag string, defaultValue bool, description string) {
	varBoolean = &defaultValue
	*options = append(*options, FlagStruct{
		LongFlag:    longFlag,
		ShortFlag:   shortFlag,
		Description: description})
}
