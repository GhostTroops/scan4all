package runner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/veo/vscan/brute"
	"github.com/veo/vscan/poc/ThinkPHP"
	"github.com/veo/vscan/poc/fastjson"
	"github.com/veo/vscan/poc/jboss"
	"github.com/veo/vscan/poc/jenkins"
	"github.com/veo/vscan/poc/shiro"
	"github.com/veo/vscan/poc/tomcat"
	"github.com/veo/vscan/poc/weblogic"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/clistats"
	"github.com/projectdiscovery/urlutil"

	// automatic fd max increase if running as root
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	pdhttputil "github.com/projectdiscovery/httputil"
	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/rawhttp"
	"github.com/remeh/sizedwaitgroup"
	customport "github.com/veo/vscan/pkg/httpx/common/customports"
	"github.com/veo/vscan/pkg/httpx/common/fileutil"
	"github.com/veo/vscan/pkg/httpx/common/httputilz"
	"github.com/veo/vscan/pkg/httpx/common/httpx"
	"github.com/veo/vscan/pkg/httpx/common/slice"
	"github.com/veo/vscan/pkg/httpx/common/stringz"
	wappalyzer "github.com/veo/vscan/pkg/httpx/fingerprint"
)

const (
	statsDisplayInterval = 5
)

// Runner is a client for running the enumeration process.
type Runner struct {
	options    *Options
	hp         *httpx.HTTPX
	wappalyzer *wappalyzer.Wappalyze
	scanopts   scanOptions
	hm         *hybrid.HybridMap
	stats      clistats.StatisticsClient
}

// New creates a new client for running enumeration process.
func New(options *Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}
	var err error
	if options.TechDetect {
		runner.wappalyzer, err = wappalyzer.New()
	}
	if err != nil {
		return nil, errors.Wrap(err, "could not create wappalyzer client")
	}

	httpxOptions := httpx.DefaultOptions
	// Enables automatically tlsgrab if tlsprobe is requested
	httpxOptions.TLSGrab = options.TLSGrab || options.TLSProbe
	httpxOptions.Timeout = time.Duration(options.Timeout) * time.Second
	httpxOptions.RetryMax = options.Retries
	httpxOptions.FollowRedirects = options.FollowRedirects
	httpxOptions.FollowHostRedirects = options.FollowHostRedirects
	httpxOptions.HTTPProxy = options.HTTPProxy
	httpxOptions.Unsafe = options.Unsafe
	httpxOptions.RequestOverride = httpx.RequestOverride{URIPath: options.RequestURI}
	httpxOptions.CdnCheck = options.OutputCDN
	httpxOptions.RandomAgent = options.RandomAgent
	httpxOptions.Deny = options.Deny
	httpxOptions.Allow = options.Allow

	var key, value string
	httpxOptions.CustomHeaders = make(map[string]string)
	for _, customHeader := range options.CustomHeaders {
		tokens := strings.SplitN(customHeader, ":", two)
		// rawhttp skips all checks
		if options.Unsafe {
			httpxOptions.CustomHeaders[customHeader] = ""
			continue
		}

		// Continue normally
		if len(tokens) < two {
			continue
		}
		key = strings.TrimSpace(tokens[0])
		value = strings.TrimSpace(tokens[1])
		httpxOptions.CustomHeaders[key] = value
	}

	runner.hp, err = httpx.New(&httpxOptions)
	if err != nil {
		gologger.Fatal().Msgf("Could not create httpx instance: %s\n", err)
	}

	var scanopts scanOptions

	if options.InputRawRequest != "" {
		var rawRequest []byte
		rawRequest, err = ioutil.ReadFile(options.InputRawRequest)
		if err != nil {
			gologger.Fatal().Msgf("Could not read raw request from '%s': %s\n", options.InputRawRequest, err)
		}

		rrMethod, rrPath, rrHeaders, rrBody, errParse := httputilz.ParseRequest(string(rawRequest), options.Unsafe)
		if errParse != nil {
			gologger.Fatal().Msgf("Could not parse raw request: %s\n", err)
		}
		scanopts.Methods = append(scanopts.Methods, rrMethod)
		scanopts.RequestURI = rrPath
		for name, value := range rrHeaders {
			httpxOptions.CustomHeaders[name] = value
		}
		scanopts.RequestBody = rrBody
		options.rawRequest = string(rawRequest)
	}

	// disable automatic host header for rawhttp if manually specified
	// as it can be malformed the best approach is to remove spaces and check for lowercase "host" word
	if options.Unsafe {
		for name := range runner.hp.CustomHeaders {
			nameLower := strings.TrimSpace(strings.ToLower(name))
			if strings.HasPrefix(nameLower, "host") {
				rawhttp.AutomaticHostHeader(false)
			}
		}
	}
	if strings.EqualFold(options.Methods, "all") {
		scanopts.Methods = pdhttputil.AllHTTPMethods()
	} else if options.Methods != "" {
		scanopts.Methods = append(scanopts.Methods, stringz.SplitByCharAndTrimSpace(options.Methods, ",")...)
	}
	if len(scanopts.Methods) == 0 {
		scanopts.Methods = append(scanopts.Methods, http.MethodGet)
	}
	runner.options.protocol = httpx.HTTPorHTTPS
	scanopts.VHost = options.VHost
	scanopts.SkipWAF = options.SkipWAF
	scanopts.OutputTitle = options.ExtractTitle
	scanopts.OutputStatusCode = options.StatusCode
	scanopts.OutputLocation = options.Location
	scanopts.OutputContentLength = options.ContentLength
	scanopts.StoreResponse = options.StoreResponse
	scanopts.StoreResponseDirectory = options.StoreResponseDir
	scanopts.OutputServerHeader = options.OutputServerHeader
	scanopts.OutputWithNoColor = options.NoColor
	scanopts.ResponseInStdout = options.responseInStdout
	scanopts.ChainInStdout = options.chainInStdout
	scanopts.OutputWebSocket = options.OutputWebSocket
	scanopts.TLSProbe = options.TLSProbe
	scanopts.CSPProbe = options.CSPProbe
	if options.RequestURI != "" {
		scanopts.RequestURI = options.RequestURI
	}
	scanopts.VHostInput = options.VHostInput
	scanopts.OutputContentType = options.OutputContentType
	scanopts.RequestBody = options.RequestBody
	scanopts.Unsafe = options.Unsafe
	scanopts.Pipeline = options.Pipeline
	scanopts.HTTP2Probe = options.HTTP2Probe
	scanopts.OutputMethod = options.OutputMethod
	scanopts.OutputIP = options.OutputIP
	scanopts.OutputCName = options.OutputCName
	scanopts.OutputCDN = options.OutputCDN
	scanopts.OutputResponseTime = options.OutputResponseTime
	scanopts.NoFallback = options.NoFallback
	scanopts.NoFallbackScheme = options.NoFallbackScheme
	scanopts.TechDetect = options.TechDetect
	scanopts.StoreChain = options.StoreChain
	scanopts.MaxResponseBodySize = options.MaxResponseBodySize
	if options.OutputExtractRegex != "" {
		if scanopts.extractRegex, err = regexp.Compile(options.OutputExtractRegex); err != nil {
			return nil, err
		}
	}

	// output verb if more than one is specified
	if len(scanopts.Methods) > 1 && !options.Silent {
		scanopts.OutputMethod = true
	}

	runner.scanopts = scanopts

	if options.ShowStatistics {
		runner.stats, err = clistats.New()
		if err != nil {
			return nil, err
		}
	}

	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return nil, err
	}
	runner.hm = hm

	return runner, nil
}

func (r *Runner) prepareInput() {
	// Check if the user requested multiple paths
	if fileutil.FileExists(r.options.RequestURIs) {
		r.options.requestURIs = fileutil.LoadFile(r.options.RequestURIs)
	} else if r.options.RequestURIs != "" {
		r.options.requestURIs = strings.Split(r.options.RequestURIs, ",")
	}

	// check if file has been provided
	var numTargets int
	numTargetsStdin, err := r.loadAndCloseFile(r.options.Naabuinput)
	if err != nil {
		gologger.Fatal().Msgf("Could read input from stdin: %s\n", err)
	}
	numTargets += numTargetsStdin

	if r.options.ShowStatistics {
		numPorts := len(customport.Ports)
		if numPorts == 0 {
			// Default Ports 80, 443
			numPorts = 2
		}

		r.stats.AddStatic("hosts", numTargets)
		r.stats.AddStatic("startedAt", time.Now())
		r.stats.AddCounter("requests", 0)
		r.stats.AddCounter("total", uint64(numTargets*numPorts))
		err := r.stats.Start(makePrintCallback(), time.Duration(statsDisplayInterval)*time.Second)
		if err != nil {
			gologger.Warning().Msgf("Could not create statistic: %s\n", err)
		}
	}
}

func (r *Runner) loadAndCloseFile(ipPorts map[string]map[int]struct{}) (numTargets int, err error) {
	for host, ports := range ipPorts {
		for port := range ports {
			target := strings.TrimSpace(fmt.Sprintf("%s:%d", host, port))
			// Used just to get the exact number of targets
			if _, ok := r.hm.Get(target); ok {
				continue
			}

			if len(r.options.requestURIs) > 0 {
				numTargets += len(r.options.requestURIs)
			} else {
				numTargets++
			}
			r.hm.Set(target, nil) //nolint
		}
	}
	return numTargets, err
}

func makePrintCallback() func(stats clistats.StatisticsClient) {
	builder := &strings.Builder{}
	return func(stats clistats.StatisticsClient) {
		builder.WriteRune('[')
		startedAt, _ := stats.GetStatic("startedAt")
		duration := time.Since(startedAt.(time.Time))
		builder.WriteString(clistats.FmtDuration(duration))
		builder.WriteRune(']')

		hosts, _ := stats.GetStatic("hosts")
		builder.WriteString(" | Hosts: ")
		builder.WriteString(clistats.String(hosts))

		requests, _ := stats.GetCounter("requests")
		total, _ := stats.GetCounter("total")

		builder.WriteString(" | RPS: ")
		builder.WriteString(clistats.String(uint64(float64(requests) / duration.Seconds())))

		builder.WriteString(" | Requests: ")
		builder.WriteString(clistats.String(requests))
		builder.WriteRune('/')
		builder.WriteString(clistats.String(total))
		builder.WriteRune(' ')
		builder.WriteRune('(')
		//nolint:gomnd // this is not a magic number
		builder.WriteString(clistats.String(uint64(float64(requests) / float64(total) * 100.0)))
		builder.WriteRune('%')
		builder.WriteRune(')')
		builder.WriteRune('\n')

		fmt.Fprintf(os.Stderr, "%s", builder.String())
		builder.Reset()
	}
}

// Close closes the httpx scan instance
func (r *Runner) Close() {
	// nolint:errcheck // ignore
	r.hm.Close()
	r.hp.Dialer.Close()
}

// RunEnumeration on targets for httpx client
func (r *Runner) RunEnumeration() {
	// Try to create output folder if it doesnt exist
	if r.options.StoreResponse && !fileutil.FolderExists(r.options.StoreResponseDir) {
		if err := os.MkdirAll(r.options.StoreResponseDir, os.ModePerm); err != nil {
			gologger.Fatal().Msgf("Could not create output directory '%s': %s\n", r.options.StoreResponseDir, err)
		}
	}

	r.prepareInput()

	// output routine
	wgoutput := sizedwaitgroup.New(1)
	wgoutput.Add()
	output := make(chan Result)
	go func(output chan Result) {
		defer wgoutput.Done()

		var f *os.File
		if r.options.Output != "" {
			var err error
			f, err = os.Create(r.options.Output)
			if err != nil {
				gologger.Fatal().Msgf("Could not create output file '%s': %s\n", r.options.Output, err)
			}
			defer f.Close() //nolint
		}
		for resp := range output {
			if resp.err != nil {
				gologger.Debug().Msgf("Failure '%s': %s\n", resp.URL, resp.err)
			}
			if resp.str == "" {
				continue
			}

			// apply matchers and filters
			if len(r.options.filterStatusCode) > 0 && slice.IntSliceContains(r.options.filterStatusCode, resp.StatusCode) {
				continue
			}
			if len(r.options.filterContentLength) > 0 && slice.IntSliceContains(r.options.filterContentLength, resp.ContentLength) {
				continue
			}
			if r.options.filterRegex != nil && r.options.filterRegex.MatchString(resp.raw) {
				continue
			}
			if r.options.OutputFilterString != "" && strings.Contains(strings.ToLower(resp.raw), strings.ToLower(r.options.OutputFilterString)) {
				continue
			}
			if len(r.options.matchStatusCode) > 0 && !slice.IntSliceContains(r.options.matchStatusCode, resp.StatusCode) {
				continue
			}
			if len(r.options.matchContentLength) > 0 && !slice.IntSliceContains(r.options.matchContentLength, resp.ContentLength) {
				continue
			}
			if r.options.matchRegex != nil && !r.options.matchRegex.MatchString(resp.raw) {
				continue
			}
			if r.options.OutputMatchString != "" && !strings.Contains(strings.ToLower(resp.raw), strings.ToLower(r.options.OutputMatchString)) {
				continue
			}

			row := resp.str
			if r.options.JSONOutput {
				row = resp.JSON(&r.scanopts)
			}
			gologger.Silent().Msgf("%s\n", row)
			if f != nil {
				//nolint:errcheck // this method needs a small refactor to reduce complexity
				f.WriteString(row + "\n")
			}
		}
	}(output)

	wg := sizedwaitgroup.New(r.options.Threads)

	r.hm.Scan(func(k, _ []byte) error {
		t := string(k)
		var reqs int
		protocol := r.options.protocol
		// attempt to parse url as is
		if u, err := url.Parse(t); err == nil {
			if r.options.NoFallbackScheme && u.Scheme == httpx.HTTP || u.Scheme == httpx.HTTPS {
				protocol = u.Scheme
			}
		}

		if len(r.options.requestURIs) > 0 {
			for _, p := range r.options.requestURIs {
				scanopts := r.scanopts.Clone()
				scanopts.RequestURI = p
				r.process(t, &wg, r.hp, protocol, scanopts, output)
				reqs++
			}
		} else {
			r.process(t, &wg, r.hp, protocol, &r.scanopts, output)
			reqs++
		}

		if r.options.ShowStatistics {
			r.stats.IncrementCounter("requests", reqs)
		}
		return nil
	})

	wg.Wait()

	close(output)

	wgoutput.Wait()
}

func (r *Runner) process(t string, wg *sizedwaitgroup.SizedWaitGroup, hp *httpx.HTTPX, protocol string, scanopts *scanOptions, output chan Result) {
	protocols := []string{protocol}
	if scanopts.NoFallback {
		protocols = []string{httpx.HTTPS, httpx.HTTP}
	}
	for target := range targets(stringz.TrimProtocol(t, scanopts.NoFallback || scanopts.NoFallbackScheme)) {
		// if no custom ports specified then test the default ones
		if len(customport.Ports) == 0 {
			for _, method := range scanopts.Methods {
				for _, prot := range protocols {
					wg.Add()
					go func(target, method, protocol string) {
						defer wg.Done()
						result := r.analyze(hp, protocol, target, method, scanopts)
						output <- result
						if scanopts.TLSProbe && result.TLSData != nil {
							scanopts.TLSProbe = false
							for _, tt := range result.TLSData.DNSNames {
								r.process(tt, wg, hp, protocol, scanopts, output)
							}
							for _, tt := range result.TLSData.CommonName {
								r.process(tt, wg, hp, protocol, scanopts, output)
							}
						}
						if scanopts.CSPProbe && result.CSPData != nil {
							scanopts.CSPProbe = false
							for _, tt := range result.CSPData.Domains {
								r.process(tt, wg, hp, protocol, scanopts, output)
							}
						}
					}(target, method, prot)
				}
			}
		}

		for port, wantedProtocol := range customport.Ports {
			for _, method := range scanopts.Methods {
				wg.Add()
				go func(port int, method, protocol string) {
					defer wg.Done()
					h, _ := urlutil.ChangePort(target, fmt.Sprint(port))
					result := r.analyze(hp, protocol, h, method, scanopts)
					output <- result
					if scanopts.TLSProbe && result.TLSData != nil {
						scanopts.TLSProbe = false
						for _, tt := range result.TLSData.DNSNames {
							r.process(tt, wg, hp, protocol, scanopts, output)
						}
						for _, tt := range result.TLSData.CommonName {
							r.process(tt, wg, hp, protocol, scanopts, output)
						}
					}
				}(port, method, wantedProtocol)
			}
		}
	}
}

// returns all the targets within a cidr range or the single target
func targets(target string) chan string {
	results := make(chan string)
	go func() {
		defer close(results)

		// A valid target does not contain:
		// *
		// spaces
		if strings.ContainsAny(target, " *") {
			return
		}

		// test if the target is a cidr
		if iputil.IsCIDR(target) {
			cidrIps, err := mapcidr.IPAddresses(target)
			if err != nil {
				return
			}
			for _, ip := range cidrIps {
				results <- ip
			}
		} else {
			results <- target
		}
	}()
	return results
}

func (r *Runner) analyze(hp *httpx.HTTPX, protocol, domain, method string, scanopts *scanOptions) Result {
	origProtocol := protocol
	if protocol == httpx.HTTPorHTTPS {
		protocol = httpx.HTTPS
	}
	retried := false
retry:
	var customHost string
	if scanopts.VHostInput {
		parts := strings.Split(domain, ",")
		//nolint:gomnd // not a magic number
		if len(parts) != 2 {
			return Result{}
		}
		domain = parts[0]
		customHost = parts[1]
	}
	URL, err := urlutil.Parse(domain)
	if err != nil {
		return Result{URL: domain, err: err}
	}
	if URL.Port == "443" || URL.Port == "8443" {
		protocol = httpx.HTTPS
	}
	URL.Scheme = protocol

	if !strings.Contains(domain, URL.Port) {
		URL.Port = ""
	}

	if !scanopts.Unsafe {
		URL.RequestURI += scanopts.RequestURI
	}
	req, err := hp.NewRequest(method, URL.String())
	if err != nil {
		return Result{URL: URL.String(), err: err}
	}
	if customHost != "" {
		req.Host = customHost
	}

	reqURI := req.URL.RequestURI()

	hp.SetCustomHeaders(req, hp.CustomHeaders)
	// We set content-length even if zero to allow net/http to follow 307/308 redirects (it fails on unknown size)
	if scanopts.RequestBody != "" {
		req.ContentLength = int64(len(scanopts.RequestBody))
		req.Body = ioutil.NopCloser(strings.NewReader(scanopts.RequestBody))
	} else {
		req.ContentLength = 0
		req.Body = nil
	}
	var requestDump []byte
	if scanopts.Unsafe {
		requestDump, err = rawhttp.DumpRequestRaw(req.Method, req.URL.String(), reqURI, req.Header, req.Body, rawhttp.DefaultOptions)
		if err != nil {
			return Result{URL: URL.String(), err: err}
		}
	} else {
		// Create a copy on the fly of the request body
		bodyBytes, _ := req.BodyBytes()
		req.Request.Body = ioutil.NopCloser(bytes.NewReader(bodyBytes))
		requestDump, err = httputil.DumpRequestOut(req.Request, true)
		if err != nil {
			return Result{URL: URL.String(), err: err}
		}
		// The original req.Body gets modified indirectly by httputil.DumpRequestOut so we set it again to nil if it was empty
		// Otherwise redirects like 307/308 would fail (as they require the body to be sent along)
		if len(bodyBytes) == 0 {
			req.Body = nil
		}
	}

	resp, err := hp.Do(req)
	if err != nil {
		if !retried && origProtocol == httpx.HTTPorHTTPS {
			if protocol == httpx.HTTPS {
				protocol = httpx.HTTP
			} else {
				protocol = httpx.HTTPS
			}
			retried = true
			goto retry
		}
		return Result{URL: URL.String(), err: err}
	}

	var fullURL string

	if resp.StatusCode >= 0 {
		fullURL = req.URL.String()
	}

	builder := &strings.Builder{}

	builder.WriteString(stringz.RemoveURLDefaultPort(fullURL))

	if scanopts.OutputStatusCode {
		builder.WriteString(" [")
		for i, chainItem := range resp.Chain {
			if !scanopts.OutputWithNoColor {
				// Color the status code based on its value
				switch {
				case chainItem.StatusCode >= http.StatusOK && chainItem.StatusCode < http.StatusMultipleChoices:
					builder.WriteString(aurora.Green(strconv.Itoa(chainItem.StatusCode)).String())
				case chainItem.StatusCode >= http.StatusMultipleChoices && chainItem.StatusCode < http.StatusBadRequest:
					builder.WriteString(aurora.Yellow(strconv.Itoa(chainItem.StatusCode)).String())
				case chainItem.StatusCode >= http.StatusBadRequest && chainItem.StatusCode < http.StatusInternalServerError:
					builder.WriteString(aurora.Red(strconv.Itoa(chainItem.StatusCode)).String())
				case resp.StatusCode > http.StatusInternalServerError:
					builder.WriteString(aurora.Bold(aurora.Yellow(strconv.Itoa(chainItem.StatusCode))).String())
				}
			} else {
				builder.WriteString(strconv.Itoa(chainItem.StatusCode))
			}
			if i != len(resp.Chain)-1 {
				builder.WriteRune(',')
			}
		}
		builder.WriteRune(']')
	}

	if scanopts.OutputLocation {
		builder.WriteString(" [")
		if !scanopts.OutputWithNoColor {
			builder.WriteString(aurora.Magenta(resp.GetHeaderPart("Location", ";")).String())
		} else {
			builder.WriteString(resp.GetHeaderPart("Location", ";"))
		}
		builder.WriteRune(']')
	}

	if scanopts.OutputMethod {
		builder.WriteString(" [")
		if !scanopts.OutputWithNoColor {
			builder.WriteString(aurora.Magenta(method).String())
		} else {
			builder.WriteString(method)
		}
		builder.WriteRune(']')
	}

	if scanopts.OutputContentLength {
		builder.WriteString(" [")
		if !scanopts.OutputWithNoColor {
			builder.WriteString(aurora.Magenta(strconv.Itoa(resp.ContentLength)).String())
		} else {
			builder.WriteString(strconv.Itoa(resp.ContentLength))
		}
		builder.WriteRune(']')
	}

	if scanopts.OutputContentType {
		builder.WriteString(" [")
		if !scanopts.OutputWithNoColor {
			builder.WriteString(aurora.Magenta(resp.GetHeaderPart("Content-Type", ";")).String())
		} else {
			builder.WriteString(resp.GetHeaderPart("Content-Type", ";"))
		}
		builder.WriteRune(']')
	}

	title := httpx.ExtractTitle(resp)
	if scanopts.OutputTitle {
		builder.WriteString(" [")
		if !scanopts.OutputWithNoColor {
			builder.WriteString(aurora.Cyan(title).String())
		} else {
			builder.WriteString(title)
		}
		builder.WriteRune(']')
	}

	serverHeader := resp.GetHeader("Server")
	if scanopts.OutputServerHeader {
		builder.WriteString(fmt.Sprintf(" [%s]", serverHeader))
	}

	var serverResponseRaw string
	var request string
	var responseHeader string
	if scanopts.ResponseInStdout {
		serverResponseRaw = string(resp.Data)
		request = string(requestDump)
		responseHeader = resp.RawHeaders
	}

	// check for virtual host
	isvhost := false
	if scanopts.VHost {
		isvhost, _ = hp.IsVirtualHost(req)
		if isvhost {
			builder.WriteString(" [vhost]")
		}
	}

	// web socket
	isWebSocket := resp.StatusCode == 101
	if scanopts.OutputWebSocket && isWebSocket {
		builder.WriteString(" [websocket]")
	}

	pipeline := false
	if scanopts.Pipeline {
		port, _ := strconv.Atoi(URL.Port)
		pipeline = hp.SupportPipeline(protocol, method, domain, port)
		if pipeline {
			builder.WriteString(" [pipeline]")
		}
	}

	var http2 bool
	// if requested probes for http2
	if scanopts.HTTP2Probe {
		http2 = hp.SupportHTTP2(protocol, method, URL.String())
		if http2 {
			builder.WriteString(" [http2]")
		}
	}
	ip := hp.Dialer.GetDialedIP(domain)
	if scanopts.OutputIP {
		builder.WriteString(fmt.Sprintf(" [%s]", ip))
	}

	var (
		ips    []string
		cnames []string
	)
	dnsData, err := hp.Dialer.GetDNSData(domain)
	if dnsData != nil && err == nil {
		ips = append(ips, dnsData.A...)
		ips = append(ips, dnsData.AAAA...)
		cnames = dnsData.CNAME
	} else {
		ips = append(ips, ip)
	}

	if scanopts.OutputCName && len(cnames) > 0 {
		// Print only the first CNAME (full list in json)
		builder.WriteString(fmt.Sprintf(" [%s]", cnames[0]))
	}

	isCDN, err := hp.CdnCheck(ip)
	if scanopts.OutputCDN && isCDN && err == nil {
		builder.WriteString(" [cdn]")
	}

	if scanopts.OutputResponseTime {
		builder.WriteString(fmt.Sprintf(" [%s]", resp.Duration))
	}
	var filePaths []string
	var technologies []string
	if !scanopts.SkipWAF {
		filePaths, technologies = brute.FileFuzz(URL.String(), resp.StatusCode, resp.ContentLength, resp.Raw)
	}
	if scanopts.TechDetect {
		SliceRemoveDuplicates := func(slice []string) []string {
			sort.Strings(slice)
			i := 0
			var j int
			for {
				if i >= len(slice)-1 {
					break
				}
				for j = i + 1; j < len(slice) && slice[i] == slice[j]; j++ {
				}
				slice = append(slice[:i+1], slice[j:]...)
				i++
			}
			return slice
		}
		matches := r.wappalyzer.Fingerprint(resp.Headers, resp.Data)
		for match := range matches {
			technologies = append(technologies, match)
		}
		technologies = SliceRemoveDuplicates(technologies)
		if !scanopts.SkipWAF {
			for tech := range technologies {
				switch technologies[tech] {
				case "Shiro":
					key := shiro.Check(URL.String())
					if key != "" {
						technologies = append(technologies, fmt.Sprintf("exp-shiro|key:%s", key))
					}
				case "登录页":
					username, password, loginurl := brute.Admin_brute(URL.String())
					if loginurl != "" {
						technologies = append(technologies, fmt.Sprintf("brute-admin|%s:%s", username, password))
					}
				case "admin登录页":
					username, password, loginurl := brute.Admin_brute(URL.String() + "/admin/")
					if loginurl != "" {
						technologies = append(technologies, fmt.Sprintf("brute-admin|%s:%s", username, password))
					}
				case "Apache Tomcat":
					username, password := brute.Tomcat_brute(URL.String())
					if username != "" {
						technologies = append(technologies, fmt.Sprintf("brute-tomcat|%s:%s", username, password))
					}
					if tomcat.CVE_2020_1938(URL.Host) {
						technologies = append(technologies, "exp-tomcat|CVE_2020_1938")
					}
					if tomcat.CVE_2017_12615(URL.String()) {
						technologies = append(technologies, "exp-tomcat|CVE_2017_12615")
					}
				case "Basic":
					username, password := brute.Basic_brute(URL.String())
					if username != "" {
						technologies = append(technologies, fmt.Sprintf("brute-basic|%s:%s", username, password))
					}
				case "weblogic":
					username, password := brute.Weblogic_brute(URL.String())
					if username != "" {
						if username == "login_page" {
							technologies = append(technologies, "weblogic_login_page")
						} else {
							technologies = append(technologies, fmt.Sprintf("brute-weblogic|%s:%s", username, password))
						}
					}
					if weblogic.CVE_2014_4210(URL.String()) {
						technologies = append(technologies, "exp-weblogic|CVE_2014_4210")
					}
					if weblogic.CVE_2017_3506(URL.String()) {
						technologies = append(technologies, "exp-weblogic|CVE_2017_3506")
					}
					if weblogic.CVE_2017_10271(URL.String()) {
						technologies = append(technologies, "exp-weblogic|CVE_2017_10271")
					}
					if weblogic.CVE_2018_2894(URL.String()) {
						technologies = append(technologies, "exp-weblogic|CVE_2018_2894")
					}
					if weblogic.CVE_2019_2725(URL.String()) {
						technologies = append(technologies, "exp-weblogic|CVE_2019_2725")
					}
					if weblogic.CVE_2019_2729(URL.String()) {
						technologies = append(technologies, "exp-weblogic|CVE_2019_2729")
					}
					if weblogic.CVE_2020_2883(URL.String()) {
						technologies = append(technologies, "exp-weblogic|CVE_2020_2883")
					}
					if weblogic.CVE_2020_14882(URL.String()) {
						technologies = append(technologies, "exp-weblogic|CVE_2020_14882")
					}
					if weblogic.CVE_2020_14883(URL.String()) {
						technologies = append(technologies, "exp-weblogic|CVE_2020_14883")
					}
					if weblogic.CVE_2021_2109(URL.String()) {
						technologies = append(technologies, "exp-weblogic|CVE_2021_2109")
					}
				case "JBoss Application Server":
					if jboss.CVE_2017_12149(URL.String()) {
						technologies = append(technologies, "exp-jboss|CVE_2017_12149")
					}
					username, password := brute.Jboss_brute(URL.String())
					if username != "" {
						technologies = append(technologies, fmt.Sprintf("brute-jboss|%s:%s", username, password))
					}
				case "JSON":
					fastjsonversion := fastjson.Check(URL.String())
					if fastjsonversion != "" {
						technologies = append(technologies, fmt.Sprintf("fastjson|%s", fastjsonversion))
					}
				case "Jenkins":
					if jenkins.Unauthorized(URL.String()) {
						technologies = append(technologies, "exp-jenkins|Unauthorized script")
					}
					if jenkins.CVE_2018_1000110(URL.String()) {
						technologies = append(technologies, "exp-jenkins|CVE_2018_1000110")
					}
					if jenkins.CVE_2018_1000861(URL.String()) {
						technologies = append(technologies, "exp-jenkins|CVE_2018_1000861")
					}
					if jenkins.CVE_2019_10003000(URL.String()) {
						technologies = append(technologies, "exp-jenkins|CVE_2019_10003000")
					}
				case "ThinkPHP":
					if ThinkPHP.RCE(URL.String()) {
						technologies = append(technologies, "exp-ThinkPHP")
					}
				}
			}
		}
		if len(technologies) > 0 {
			sort.Strings(technologies)
			technologies := strings.Join(technologies, ",")
			builder.WriteString(" [")
			if !scanopts.OutputWithNoColor {
				builder.WriteString(aurora.Magenta(technologies).String())
			} else {
				builder.WriteString(technologies)
			}
			builder.WriteRune(']')
		}
	}

	// extract regex
	if scanopts.extractRegex != nil {
		matches := scanopts.extractRegex.FindAllString(string(resp.Data), -1)
		if len(matches) > 0 {
			builder.WriteString(" [" + strings.Join(matches, ",") + "]")
		}
	}

	var finalURL string
	if resp.HasChain() {
		finalURL = resp.GetChainLastURL()
	}

	if resp.HasChain() {
		builder.WriteString(" [ ")
		if !scanopts.OutputWithNoColor {
			builder.WriteString(aurora.Magenta(finalURL).String())
		} else {
			builder.WriteString(finalURL)
		}
		builder.WriteRune(' ')
		builder.WriteRune(']')
	}

	if len(filePaths) > 0 {
		file_paths := strings.Join(filePaths, "\",\""+URL.String())
		builder.WriteString(" [file_fuzz：")
		if !scanopts.OutputWithNoColor {
			builder.WriteString(aurora.Magenta("\"" + URL.String() + file_paths).String())
		} else {
			builder.WriteString("\"" + URL.String() + file_paths)
		}
		builder.WriteRune('"')
		builder.WriteRune(']')
	}

	// store responses or chain in directory
	if scanopts.StoreResponse || scanopts.StoreChain {
		domainFile := strings.ReplaceAll(urlutil.TrimScheme(URL.String()), ":", ".")

		// On various OS the file max file name length is 255 - https://serverfault.com/questions/9546/filename-length-limits-on-linux
		// Truncating length at 255
		if len(domainFile) >= maxFileNameLength {
			// leaving last 4 bytes free to append ".txt"
			domainFile = domainFile[:maxFileNameLength-1]
		}

		domainFile = strings.ReplaceAll(domainFile, "/", "_") + ".txt"
		// store response
		responsePath := path.Join(scanopts.StoreResponseDirectory, domainFile)
		respRaw := resp.Raw
		if len(respRaw) > scanopts.MaxResponseBodySize {
			respRaw = respRaw[:scanopts.MaxResponseBodySize]
		}
		writeErr := ioutil.WriteFile(responsePath, []byte(respRaw), 0644)
		if writeErr != nil {
			gologger.Warning().Msgf("Could not write response, at path '%s', to disk: %s", responsePath, writeErr)
		}
		if scanopts.StoreChain && resp.HasChain() {
			domainFile = strings.ReplaceAll(domainFile, ".txt", ".chain.txt")
			responsePath := path.Join(scanopts.StoreResponseDirectory, domainFile)
			writeErr := ioutil.WriteFile(responsePath, []byte(resp.GetChain()), 0644)
			if writeErr != nil {
				gologger.Warning().Msgf("Could not write response, at path '%s', to disk: %s", responsePath, writeErr)
			}
		}
	}

	parsed, err := urlutil.Parse(fullURL)
	if err != nil {
		return Result{URL: fullURL, err: errors.Wrap(err, "could not parse url")}
	}

	finalPort := parsed.Port
	if finalPort == "" {
		if parsed.Scheme == "http" {
			finalPort = "80"
		} else {
			finalPort = "443"
		}
	}
	finalPath := parsed.RequestURI
	if finalPath == "" {
		finalPath = "/"
	}

	hasher := sha256.New()
	_, _ = hasher.Write(resp.Data)
	bodySha := hex.EncodeToString(hasher.Sum(nil))
	hasher.Reset()

	_, _ = hasher.Write([]byte(resp.RawHeaders))
	headersSha := hex.EncodeToString(hasher.Sum(nil))

	var chainStatusCodes []int
	if resp.HasChain() {
		chainStatusCodes = append(chainStatusCodes, resp.GetChainStatusCodes()...)
	}
	var chainItems []httpx.ChainItem
	if scanopts.ChainInStdout && resp.HasChain() {
		chainItems = append(chainItems, resp.GetChainAsSlice()...)
	}

	return Result{
		Timestamp:        time.Now(),
		Request:          request,
		ResponseHeader:   responseHeader,
		Scheme:           parsed.Scheme,
		Port:             finalPort,
		Path:             finalPath,
		BodySHA256:       bodySha,
		HeaderSHA256:     headersSha,
		raw:              resp.Raw,
		URL:              fullURL,
		ContentLength:    resp.ContentLength,
		ChainStatusCodes: chainStatusCodes,
		Chain:            chainItems,
		StatusCode:       resp.StatusCode,
		Location:         resp.GetHeaderPart("Location", ";"),
		ContentType:      resp.GetHeaderPart("Content-Type", ";"),
		Title:            title,
		str:              builder.String(),
		VHost:            isvhost,
		WebServer:        serverHeader,
		ResponseBody:     serverResponseRaw,
		WebSocket:        isWebSocket,
		TLSData:          resp.TLSData,
		CSPData:          resp.CSPData,
		Pipeline:         pipeline,
		HTTP2:            http2,
		Method:           method,
		Host:             ip,
		A:                ips,
		CNAMEs:           cnames,
		CDN:              isCDN,
		ResponseTime:     resp.Duration.String(),
		Technologies:     technologies,
		FinalURL:         finalURL,
	}
}

// Result of a scan
type Result struct {
	Timestamp        time.Time `json:"timestamp,omitempty"`
	Request          string    `json:"request,omitempty"`
	ResponseHeader   string    `json:"response-header,omitempty"`
	Scheme           string    `json:"scheme,omitempty"`
	Port             string    `json:"port,omitempty"`
	Path             string    `json:"path,omitempty"`
	BodySHA256       string    `json:"body-sha256,omitempty"`
	HeaderSHA256     string    `json:"header-sha256,omitempty"`
	A                []string  `json:"a,omitempty"`
	CNAMEs           []string  `json:"cnames,omitempty"`
	raw              string
	URL              string `json:"url,omitempty"`
	Location         string `json:"location,omitempty"`
	Title            string `json:"title,omitempty"`
	str              string
	err              error
	WebServer        string            `json:"webserver,omitempty"`
	ResponseBody     string            `json:"response-body,omitempty"`
	ContentType      string            `json:"content-type,omitempty"`
	Method           string            `json:"method,omitempty"`
	Host             string            `json:"host,omitempty"`
	ContentLength    int               `json:"content-length,omitempty"`
	ChainStatusCodes []int             `json:"chain-status-codes,omitempty"`
	StatusCode       int               `json:"status-code,omitempty"`
	TLSData          *httpx.TLSData    `json:"tls-grab,omitempty"`
	CSPData          *httpx.CSPData    `json:"csp,omitempty"`
	VHost            bool              `json:"vhost,omitempty"`
	WebSocket        bool              `json:"websocket,omitempty"`
	Pipeline         bool              `json:"pipeline,omitempty"`
	HTTP2            bool              `json:"http2,omitempty"`
	CDN              bool              `json:"cdn,omitempty"`
	ResponseTime     string            `json:"response-time,omitempty"`
	Technologies     []string          `json:"technologies,omitempty"`
	Chain            []httpx.ChainItem `json:"chain,omitempty"`
	FinalURL         string            `json:"final-url,omitempty"`
}

// JSON the result
func (r Result) JSON(scanopts *scanOptions) string { //nolint
	if scanopts != nil && len(r.ResponseBody) > scanopts.MaxResponseBodySize {
		r.ResponseBody = r.ResponseBody[:scanopts.MaxResponseBodySize]
	}

	if js, err := json.Marshal(r); err == nil {
		return string(js)
	}

	return ""
}
