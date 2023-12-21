package runner

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/GhostTroops/scan4all/pkg/fingerprint"
	"github.com/GhostTroops/scan4all/projectdiscovery/nuclei_Yaml"
	"github.com/GhostTroops/scan4all/webScan"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/iputil"
	runner3 "github.com/projectdiscovery/naabu/v2/pkg/runner"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/uncover/sources/agent/shodanidb"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	httpxrunner "github.com/GhostTroops/scan4all/pkg/httpx/runner"

	"github.com/GhostTroops/scan4all/pkg/naabu/v2/pkg/privileges"
	"github.com/GhostTroops/scan4all/pkg/naabu/v2/pkg/scan"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/blackrock"
	"github.com/projectdiscovery/clistats"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/mapcidr"

	"github.com/remeh/sizedwaitgroup"
	"go.uber.org/ratelimit"
)

// Runner is an instance of the port enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options       *Options
	targetsFile   string
	scanner       *scan.Scanner
	limiter       ratelimit.Limiter
	wgscan        sizedwaitgroup.SizedWaitGroup
	dnsclient     *dnsx.DNSX
	stats         *clistats.Statistics
	streamChannel chan *net.IPNet
	mB            map[string]bool
}

var Naabubuffer = bytes.Buffer{}

func (r *Runner) Httpxrun(buf *bytes.Buffer, options *runner3.Options) error {
	if nil != buf {
		httpxrunner.Naabubuffer = *buf
	} else {
		httpxrunner.Naabubuffer = Naabubuffer
	}
	Cookie := util.GetVal("Cookie")
	if !strings.Contains(Cookie, "rememberMe") {
		Cookie = "Cookie: " + Cookie + ";rememberMe=123" // add
	}
	//log.Printf("%+v", httpxrunner.Naabubuffer.String())
	// 集成nuclei
	//log.Println("httpxrunner.Naabubuffer = ", httpxrunner.Naabubuffer.String())
	//Naabubuffer1 := bytes.Buffer{}
	//Naabubuffer1.Write(httpxrunner.Naabubuffer.Bytes())
	httpxoptions := httpxrunner.ParseOptions()

	opts := map[string]interface{}{}
	if "" != Cookie {
		if nil == httpxoptions.CustomHeaders {
			httpxoptions.CustomHeaders = []string{Cookie}
		} else {
			httpxoptions.CustomHeaders.Set(Cookie)
		}
		var a []string
		a = append(a, httpxoptions.CustomHeaders...)
		opts["CustomHeaders"] = a
		util.CustomHeaders = append(util.CustomHeaders, a...)
	}
	//var axx1 []*runner2.Runner

	util.DoSyncFunc(func() {
		if util.GetValAsBool("enableWebScan") {
			util.DoSyncFunc(func() {
				webScan.CheckUrls(&httpxrunner.Naabubuffer)
			})
		}
		nuclei_Yaml.RunNuclei(&httpxrunner.Naabubuffer)
	})
	// 指纹去重复 请求路径
	if "" != fingerprint.FgDictFile {
		httpxoptions.RequestURIs = fingerprint.FgDictFile
		//fmt.Println("httpxoptions.RequestURIs: ", httpxoptions.RequestURIs)
	}

	httpxoptions.Output = r.options.Output
	httpxoptions.CSVOutput = r.options.CSV
	httpxoptions.JSONOutput = r.options.JSON
	httpxoptions.HTTPProxy = r.options.Proxy
	httpxoptions.Threads = r.options.Threads
	httpxoptions.Verbose = r.options.Verbose
	httpxoptions.NoColor = r.options.NoColor
	httpxoptions.Silent = r.options.Silent
	httpxoptions.Version = r.options.Version
	httpxoptions.RateLimit = r.options.Rate

	httpxoptions.NoPOC = r.options.NoPOC
	httpxoptions.CeyeApi = r.options.CeyeApi
	httpxoptions.CeyeDomain = r.options.CeyeDomain
	util.CeyeApi = r.options.CeyeApi
	util.CeyeDomain = r.options.CeyeDomain
	util.HttpProxy = r.options.Proxy
	util.Fuzzthreads = r.options.Threads

	if httpxoptions.RateLimit == 0 {
		httpxoptions.RateLimit = 1
	}

	//httpxoptions.NoColor = r.options.NoColor
	//httpxoptions.Silent = r.options.Silent
	//httpxoptions.Output = r.options.Output
	//httpxoptions.HTTPProxy = r.options.Proxy
	//httpxoptions.NoPOC = r.options.NoPOC
	//jndi.JndiAddress = r.options.LocalJndiAddress
	//brute.SkipAdminBrute = r.options.SkipAdminBrute
	//pkg.CeyeApi = r.options.CeyeApi
	//pkg.CeyeDomain = r.options.CeyeDomain
	//pkg.HttpProxy = r.options.Proxy
	//pkg.NoColor = r.options.NoColor
	//pkg.Output = r.options.Output
	//httpxoptions.Naabuinput = Naabuipports
	//if jndi.JndiAddress != "" {
	//	go jndi.JndiServer()
	//}

	// json 控制参数
	httpxoptions = util.ParseOption[httpxrunner.Options]("httpx", httpxoptions)
	rx, err := httpxrunner.New(httpxoptions)
	if err != nil {
		return err
	}
	rx.RunEnumeration()
	rx.Close()
	// wait nuclei
	return nil
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists, etc
func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{
		options: options,
		mB:      make(map[string]bool),
	}
	runner.streamChannel = make(chan *net.IPNet)

	excludedIps, err := parseExcludedIps(options)
	if err != nil {
		return nil, err
	}

	scanner, err := scan.NewScanner(&scan.Options{
		Timeout:     time.Duration(options.Timeout) * time.Millisecond,
		Retries:     options.Retries,
		Rate:        options.Rate,
		Debug:       options.Debug,
		ExcludeCdn:  options.ExcludeCDN,
		ExcludedIps: excludedIps,
		Proxy:       options.Proxy,
		Stream:      options.Stream,
	})
	if err != nil {
		return nil, err
	}
	runner.scanner = scanner
	options = util.ParseOption[Options]("naabu", options)
	runner.scanner.Ports, err = ParsePorts(options)
	if err != nil {
		return nil, fmt.Errorf("could not parse ports: %s", err)
	}

	dnsOptions := dnsx.DefaultOptions
	dnsOptions.MaxRetries = runner.options.Retries
	dnsOptions.Hostsfile = true
	if len(runner.options.baseResolvers) > 0 {
		dnsOptions.BaseResolvers = runner.options.baseResolvers
	}
	if err != nil {
		return nil, err
	}
	dnsOptions = *util.ParseOption[dnsx.Options]("naabu_dns", &dnsOptions)
	dnsclient, err := dnsx.New(dnsOptions)
	if err != nil {
		return nil, err
	}
	runner.dnsclient = dnsclient

	if options.EnableProgressBar {
		stats, err := clistats.New()
		if err != nil {
			gologger.Warning().Msgf("Couldn't create progress engine: %s\n", err)
		} else {
			runner.stats = stats
		}
	}

	return runner, nil
}

// RunEnumeration runs the ports enumeration flow on the targets specified
func (r *Runner) RunEnumeration() error {
	defer r.Close()

	if privileges.IsPrivileged && r.options.ScanType == SynScan {
		// Set values if those were specified via cli
		if err := r.SetSourceIPAndInterface(); err != nil {
			// Otherwise try to obtain them automatically
			err = r.scanner.TuneSource(ExternalTargetForTune)
			if err != nil {
				return err
			}
		}
		err := r.scanner.SetupHandlers()
		if err != nil {
			return err
		}
		r.BackgroundWorkers()
	}

	if r.options.Stream {
		r.Load() //nolint
	} else {
		err := r.Load()
		if err != nil {
			return err
		}
	}

	// Scan workers
	r.wgscan = sizedwaitgroup.New(r.options.Rate)
	r.limiter = ratelimit.New(r.options.Rate)

	shouldUseRawPackets := isOSSupported() && privileges.IsPrivileged && r.options.ScanType == SynScan

	switch {
	case r.options.Stream && !r.options.Passive: // stream active
		r.scanner.State = scan.Scan
		for cidr := range r.streamChannel {
			s01 := cidr.String()
			//if govalidator.IsDNSName(s01) { // 转ip
			//
			//}
			if err := r.scanner.IPRanger.Add(s01); err != nil {
				gologger.Warning().Msgf("Couldn't track %s in scan results: %s\n", cidr, err)
			}
			// 可以优化基于nmap
			ipStream, _ := mapcidr.IPAddressesAsStream(s01)
			for ip := range ipStream {
				for _, port := range r.scanner.Ports {
					r.limiter.Take()
					go func(ip string, port int) {
						if shouldUseRawPackets {
							r.RawSocketEnumeration(ip, port)
						} else {
							r.wgscan.Add()

							go r.handleHostPort(ip, port)
						}
					}(ip, port)
				}
			}
		}
		r.wgscan.Wait()
		r.handleOutput()
		return nil
	case r.options.Stream && r.options.Passive: // stream passive
		// create retryablehttp instance
		httpClient := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
		r.scanner.State = scan.Scan
		for cidr := range r.streamChannel {
			if err := r.scanner.IPRanger.Add(cidr.String()); err != nil {
				gologger.Warning().Msgf("Couldn't track %s in scan results: %s\n", cidr, err)
			}
			ipStream, _ := mapcidr.IPAddressesAsStream(cidr.String())
			for ip := range ipStream {
				r.wgscan.Add()
				go func(ip string) {
					defer r.wgscan.Done()

					// obtain ports from shodan idb
					shodanURL := fmt.Sprintf(shodanidb.URL, url.QueryEscape(ip))
					request, err := retryablehttp.NewRequest(http.MethodGet, shodanURL, nil)
					if err != nil {
						gologger.Warning().Msgf("Couldn't create http request for %s: %s\n", ip, err)
						return
					}
					r.limiter.Take()
					response, err := httpClient.Do(request)
					if err != nil {
						gologger.Warning().Msgf("Couldn't retrieve http response for %s: %s\n", ip, err)
						return
					}
					if response.StatusCode != http.StatusOK {
						gologger.Warning().Msgf("Couldn't retrieve data for %s, server replied with status code: %d\n", ip, response.StatusCode)
						return
					}

					// unmarshal the response
					data := &shodanidb.ShodanResponse{}
					if err := json.NewDecoder(response.Body).Decode(data); err != nil {
						gologger.Warning().Msgf("Couldn't unmarshal json data for %s: %s\n", ip, err)
						return
					}

					for _, port := range data.Ports {
						r.scanner.ScanResults.AddPort(ip, port)
					}
				}(ip)
			}
		}
		r.wgscan.Wait()

		// Validate the hosts if the user has asked for second step validation
		if r.options.Verify {
			r.ConnectVerification()
		}

		r.handleOutput()
		return nil
	default:
		// shrinks the ips to the minimum amount of cidr
		var targets []*net.IPNet
		r.scanner.IPRanger.Hosts.Scan(func(k, v []byte) error {
			targets = append(targets, iputil.ToCidr(string(k)))
			return nil
		})
		targets, _ = mapcidr.CoalesceCIDRs(targets)
		var targetsCount, portsCount uint64
		for _, target := range targets {
			targetsCount += mapcidr.AddressCountIpnet(target)
		}
		portsCount = uint64(len(r.scanner.Ports))

		r.scanner.State = scan.Scan
		Range := targetsCount * portsCount
		if r.options.EnableProgressBar {
			r.stats.AddStatic("ports", portsCount)
			r.stats.AddStatic("hosts", targetsCount)
			r.stats.AddStatic("retries", r.options.Retries)
			r.stats.AddStatic("startedAt", time.Now())
			r.stats.AddCounter("packets", uint64(0))
			r.stats.AddCounter("errors", uint64(0))
			r.stats.AddCounter("total", Range*uint64(r.options.Retries))
			if err := r.stats.Start(); err != nil {
				gologger.Warning().Msgf("Couldn't start statistics: %s", err)
			}
		}

		// Retries are performed regardless of the previous scan results due to network unreliability
		for currentRetry := 0; currentRetry < r.options.Retries; currentRetry++ {
			if currentRetry < r.options.ResumeCfg.Retry {
				gologger.Debug().Msgf("Skipping Retry: %d\n", currentRetry)
				continue
			}

			// Use current time as seed
			currentSeed := time.Now().UnixNano()
			r.options.ResumeCfg.RLock()
			if r.options.ResumeCfg.Seed > 0 {
				currentSeed = r.options.ResumeCfg.Seed
			}
			r.options.ResumeCfg.RUnlock()

			// keep track of current retry and seed for resume
			r.options.ResumeCfg.Lock()
			r.options.ResumeCfg.Retry = currentRetry
			r.options.ResumeCfg.Seed = currentSeed
			r.options.ResumeCfg.Unlock()
			// 可以优化基于nmap
			b := blackrock.New(int64(Range), currentSeed)
			for index := int64(0); index < int64(Range); index++ {
				xxx := b.Shuffle(index)
				ipIndex := xxx / int64(portsCount)
				portIndex := int(xxx % int64(portsCount))
				ip := r.PickIP(targets, ipIndex)
				port := r.PickPort(portIndex)

				r.options.ResumeCfg.RLock()
				resumeCfgIndex := r.options.ResumeCfg.Index
				r.options.ResumeCfg.RUnlock()
				if index < resumeCfgIndex {
					gologger.Debug().Msgf("Skipping \"%s:%d\": Resume - Port scan already completed\n", ip, port)
					continue
				}

				r.limiter.Take()
				//resume cfg logic
				r.options.ResumeCfg.Lock()
				r.options.ResumeCfg.Index = index
				r.options.ResumeCfg.Unlock()
				// connect scan
				go func(port int) {
					if shouldUseRawPackets {
						r.RawSocketEnumeration(ip, port)
					} else {
						r.wgscan.Add()

						go r.handleHostPort(ip, port)
					}
					if r.options.EnableProgressBar {
						r.stats.IncrementCounter("packets", 1)
					}
				}(port)
			}

			r.wgscan.Wait()

			r.options.ResumeCfg.Lock()
			if r.options.ResumeCfg.Seed > 0 {
				r.options.ResumeCfg.Seed = 0
			}
			r.options.ResumeCfg.Unlock()
		}

		if r.options.WarmUpTime > 0 {
			time.Sleep(time.Duration(r.options.WarmUpTime) * time.Second)
		}

		r.scanner.State = scan.Done

		// Validate the hosts if the user has asked for second step validation
		if r.options.Verify {
			r.ConnectVerification()
		}

		r.handleOutput()

		// handle nmap
		return r.handleNmap()
	}
}

func (r *Runner) ShowScanResultOnExit() {
	r.handleOutput()
	err := r.handleNmap()
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}
}

// Close runner instance
func (r *Runner) Close() {
	os.RemoveAll(r.targetsFile)
	r.scanner.IPRanger.Hosts.Close()
	r.scanner.State = scan.Done
	r.scanner.Close()
	// 下面 n 行会导致异常
	//close(r.streamChannel)
	//r.scanner.CleanupHandlers()
	//r.scanner.Close()
	//r.wgscan
}

// PickIP randomly
func (r *Runner) PickIP(targets []*net.IPNet, index int64) string {
	for _, target := range targets {
		subnetIpsCount := int64(mapcidr.AddressCountIpnet(target))
		if index < subnetIpsCount {
			return r.PickSubnetIP(target, index)
		}
		index -= subnetIpsCount
	}

	return ""
}

func (r *Runner) PickSubnetIP(network *net.IPNet, index int64) string {
	return mapcidr.Inet_ntoa(mapcidr.Inet_aton(network.IP) + index).String()
}

func (r *Runner) PickPort(index int) int {
	return r.scanner.Ports[index]
}

func (r *Runner) ConnectVerification() {
	r.scanner.State = scan.Scan
	var swg sync.WaitGroup
	limiter := ratelimit.New(r.options.Rate)

	for host, ports := range r.scanner.ScanResults.IPPorts {
		limiter.Take()
		swg.Add(1)
		go func(host string, ports map[int]struct{}) {
			defer swg.Done()
			results := r.scanner.ConnectVerify(host, ports)
			r.scanner.ScanResults.SetPorts(host, results)
		}(host, ports)
	}

	swg.Wait()
}

func (r *Runner) BackgroundWorkers() {
	r.scanner.StartWorkers()
}

func (r *Runner) RawSocketEnumeration(ip string, port int) {
	// skip invalid combinations
	r.handleHostPortSyn(ip, port)
}

// check if an ip can be scanned in case CDN exclusions are enabled
func (r *Runner) canIScanIfCDN(host string, port int) bool {
	// if CDN ips are not excluded all scans are allowed
	if !r.options.ExcludeCDN {
		return true
	}

	// if exclusion is enabled, but the ip is not part of the CDN ips range we can scan
	if ok, _, err := r.scanner.CdnCheck(host); err == nil && !ok {
		return true
	}

	// If the cdn is part of the CDN ips range - only ports 80 and 443 are allowed
	return port == 80 || port == 443
}

func (r *Runner) handleHostPort(host string, port int) {
	defer r.wgscan.Done()

	// performs cdn scan exclusions checks
	if !r.canIScanIfCDN(host, port) {
		gologger.Debug().Msgf("Skipping cdn target: %s:%d\n", host, port)
		return
	}

	if r.scanner.ScanResults.IPHasPort(host, port) {
		return
	}

	r.limiter.Take()
	open, err := r.scanner.ConnectPort(host, port, time.Duration(r.options.Timeout)*time.Millisecond)
	if open && err == nil {
		r.scanner.ScanResults.AddPort(host, port)
	}
}

func (r *Runner) handleHostPortSyn(host string, port int) {
	// performs cdn scan exclusions checks
	if !r.canIScanIfCDN(host, port) {
		gologger.Debug().Msgf("Skipping cdn target: %s:%d\n", host, port)
		return
	}

	r.limiter.Take()
	r.scanner.EnqueueTCP(host, port, scan.SYN)
}

func (r *Runner) SetSourceIPAndInterface() error {
	if r.options.SourceIP != "" && r.options.Interface != "" {
		r.scanner.SourceIP = net.ParseIP(r.options.SourceIP)
		if r.options.Interface != "" {
			var err error
			r.scanner.NetworkInterface, err = net.InterfaceByName(r.options.Interface)
			if err != nil {
				return err
			}
		}
	}

	return fmt.Errorf("source Ip and Interface not specified")
}

func (r *Runner) handleOutput() {
	var (
		file   *os.File
		err    error
		output string
	)
	// In case the user has given an output file, write all the found
	// ports to the output file.
	if r.options.Output != "" {
		output = r.options.Output
		util.Output = output

		// create path if not existing
		outputFolder := filepath.Dir(output)
		if fileutil.FolderExists(outputFolder) {
			mkdirErr := os.MkdirAll(outputFolder, 0700)
			if mkdirErr != nil {
				gologger.Error().Msgf("Could not create output folder %s: %s\n", outputFolder, mkdirErr)
				return
			}
		}

		file, err = os.Create(output)
		if err != nil {
			gologger.Error().Msgf("Could not create file %s: %s\n", output, err)
			return
		}
		defer file.Close()
	}
	csvFileHeaderEnabled := true
	for hostIP, ports := range r.scanner.ScanResults.IPPorts {
		csvHeaderEnabled := true
		dt, err := r.scanner.IPRanger.GetHostsByIP(hostIP)
		if err != nil {
			continue
		}
		buffer := bytes.Buffer{}
		writer := csv.NewWriter(&buffer)
		for _, host := range dt {
			buffer.Reset()
			if host == "ip" {
				host = hostIP
			}
			log.Printf("%s found ports: %d", hostIP, len(ports))
			for port := range ports {
				Add2Naabubuffer(fmt.Sprintf("%s:%d\n", host, port))
			}
			gologger.Info().Msgf("Found %d ports on host %s (%s)\n", len(ports), host, hostIP)
			// console output
			if r.options.JSON || r.options.CSV {
				data := &Result{IP: hostIP, TimeStamp: time.Now().UTC()}
				if host != hostIP {
					data.Host = host
				}
				for port := range ports {
					data.Port = port
					if r.options.JSON {
						b, marshallErr := data.JSON()
						if marshallErr != nil {
							continue
						}
						buffer.Write([]byte(fmt.Sprintf("%s\n", b)))
					} else if r.options.CSV {
						if csvHeaderEnabled {
							writeCSVHeaders(data, writer)
							csvHeaderEnabled = false
						}
						writeCSVRow(data, writer)
					}
				}
			}
			if r.options.JSON {
				gologger.Silent().Msgf("%s", buffer.String())
			} else if r.options.CSV {
				writer.Flush()
				gologger.Silent().Msgf("%s", buffer.String())
			} else {
				aN := []int{}
				for port := range ports {
					aN = append(aN, port)
					gologger.Silent().Msgf("%s:%d\n", host, port)
				}
				util.SendAData[int](host, aN, util.Naabu)
			}
			// file output
			if file != nil {
				if r.options.JSON {
					err = WriteJSONOutput(host, hostIP, ports, file)
				} else if r.options.CSV {
					err = WriteCsvOutput(host, hostIP, ports, csvFileHeaderEnabled, file)
				} else {
					err = WriteHostOutput(host, ports, file)
				}
				if err != nil {
					gologger.Error().Msgf("Could not write results to file %s for %s: %s\n", output, host, err)
				}
			}

			if r.options.OnResult != nil {
				r.options.OnResult(host, hostIP, mapKeysToSliceInt(ports))
			}
		}
		csvFileHeaderEnabled = false
	}
}
func writeCSVHeaders(data *Result, writer *csv.Writer) {
	headers, err := data.CSVHeaders()
	if err != nil {
		gologger.Error().Msgf(err.Error())
		return
	}

	if err := writer.Write(headers); err != nil {
		errMsg := errors.Wrap(err, "Could not write headers")
		gologger.Error().Msgf(errMsg.Error())
	}
}

func writeCSVRow(data *Result, writer *csv.Writer) {
	rowData, err := data.CSVFields()
	if err != nil {
		gologger.Error().Msgf(err.Error())
		return
	}
	if err := writer.Write(rowData); err != nil {
		errMsg := errors.Wrap(err, "Could not write row")
		gologger.Error().Msgf(errMsg.Error())
	}
}
