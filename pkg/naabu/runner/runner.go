package runner

import (
	"encoding/json"
	"fmt"
	"github.com/veo/vscan/brute"
	"github.com/veo/vscan/pkg"
	httpxrunner "github.com/veo/vscan/pkg/httpx/runner"
	"github.com/veo/vscan/pkg/jndi"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/blackrock"
	"github.com/projectdiscovery/clistats"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ipranger"
	"github.com/projectdiscovery/mapcidr"
	"github.com/remeh/sizedwaitgroup"
	"github.com/veo/vscan/pkg/naabu/scan"
	"go.uber.org/ratelimit"
)

const (
	tickduration = 5
)

// Runner is an instance of the port enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options     *Options
	targetsFile string
	scanner     *scan.Scanner
	limiter     ratelimit.Limiter
	wgscan      sizedwaitgroup.SizedWaitGroup
	dnsclient   *dnsx.DNSX
	stats       *clistats.Statistics
}

var Naabuipports = make(map[string]map[int]struct{})

func (r *Runner) httpxrun() error {
	for hostIP, ports := range r.scanner.ScanResults.IPPorts {
		dt, err := r.scanner.IPRanger.GetHostsByIP(hostIP)
		if err != nil {
			continue
		}
		for _, host := range dt {
			if host == "ip" {
				host = hostIP
			}
			for port := range ports {
				if _, ok := Naabuipports[host]; !ok {
					Naabuipports[host] = make(map[int]struct{})
				}
				Naabuipports[host][port] = struct{}{}
			}
		}
	}
	httpxoptions := httpxrunner.ParseOptions()
	httpxoptions.CeyeApi = r.options.CeyeApi
	httpxoptions.CeyeDomain = r.options.CeyeDomain
	httpxoptions.NoColor = r.options.NoColor
	httpxoptions.Silent = r.options.Silent
	httpxoptions.Output = r.options.Output
	httpxoptions.HTTPProxy = r.options.Proxy
	jndi.JndiAddress = r.options.LocalJndiAddress
	brute.SkipAdminBrute = r.options.SkipAdminBrute
	pkg.CeyeApi = r.options.CeyeApi
	pkg.CeyeDomain = r.options.CeyeDomain
	pkg.HttpProxy = r.options.Proxy
	pkg.NoColor = r.options.NoColor
	pkg.Output = r.options.Output
	httpxoptions.Naabuinput = Naabuipports
	if jndi.JndiAddress != "" {
		go jndi.JndiServer()
	}
	rx, err := httpxrunner.New(httpxoptions)
	if err != nil {
		return err
	}
	rx.RunEnumeration()
	rx.Close()
	return nil
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists, etc
func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}

	excludedIps, err := parseExcludedIps(options)
	if err != nil {
		return nil, err
	}

	scanner, err := scan.NewScanner(&scan.Options{
		Timeout:     time.Duration(options.Timeout) * time.Millisecond,
		Retries:     options.Retries,
		Rate:        options.Rate,
		Debug:       options.Debug,
		Root:        isRoot(),
		ExcludeCdn:  options.ExcludeCDN,
		ExcludedIps: excludedIps,
	})
	if err != nil {
		return nil, err
	}
	runner.scanner = scanner

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

	if isRoot() && r.options.ScanType == SynScan {
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

	err := r.Load()
	if err != nil {
		return err
	}

	// Scan workers
	r.wgscan = sizedwaitgroup.New(r.options.Rate)
	r.limiter = ratelimit.New(r.options.Rate)

	// shrinks the ips to the minimum amount of cidr
	var targets []*net.IPNet
	r.scanner.IPRanger.Hosts.Scan(func(k, v []byte) error {
		targets = append(targets, ipranger.ToCidr(string(k)))
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
		if err := r.stats.Start(makePrintCallback(), tickduration*time.Second); err != nil {
			gologger.Warning().Msgf("Couldn't start statistics: %s\n", err)
		}
	}

	osSupported := isOSSupported()
	// Retries are performed regardless of the previous scan results due to network unreliability
	for currentRetry := 0; currentRetry < r.options.Retries; currentRetry++ {
		// Use current time as seed
		b := blackrock.New(int64(Range), time.Now().UnixNano())
		for index := int64(0); index < int64(Range); index++ {
			xxx := b.Shuffle(index)
			ipIndex := xxx / int64(portsCount)
			portIndex := int(xxx % int64(portsCount))
			ip := r.PickIP(targets, ipIndex)
			port := r.PickPort(portIndex)

			r.limiter.Take()
			// connect scan
			if osSupported && isRoot() && r.options.ScanType == SynScan {
				r.RawSocketEnumeration(ip, port)
			} else {
				r.wgscan.Add()
				go r.handleHostPort(ip, port)
			}
			if r.options.EnableProgressBar {
				r.stats.IncrementCounter("packets", 1)
			}
		}
	}

	r.wgscan.Wait()
	_ = r.stats.Stop()
	gologger.Info().Msg("Port scan over,web scan starting")
	r.httpxrun()

	if r.options.WarmUpTime > 0 {
		time.Sleep(time.Duration(r.options.WarmUpTime) * time.Second)
	}

	r.scanner.State = scan.Done

	// Validate the hosts if the user has asked for second step validation
	if r.options.Verify {
		r.ConnectVerification()
	}

	//r.handleOutput()

	// handle nmap
	r.handleNmap()

	return nil
}

// Close runner instance
func (r *Runner) Close() {
	os.RemoveAll(r.targetsFile)
	r.scanner.IPRanger.Hosts.Close()
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
	if ok, err := r.scanner.CdnCheck(host); err == nil && !ok {
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

	open, err := scan.ConnectPort(host, port, time.Duration(r.options.Timeout)*time.Millisecond)
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

		// create path if not existing
		outputFolder := filepath.Dir(output)
		if _, statErr := os.Stat(outputFolder); os.IsNotExist(statErr) {
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
	for hostIP, ports := range r.scanner.ScanResults.IPPorts {
		dt, err := r.scanner.IPRanger.GetHostsByIP(hostIP)
		if err != nil {
			continue
		}

		for _, host := range dt {
			if host == "ip" {
				host = hostIP
			}
			gologger.Info().Msgf("Found %d ports on host %s (%s)\n", len(ports), host, hostIP)

			// console output
			if r.options.JSON {
				data := JSONResult{IP: hostIP}
				if host != hostIP {
					data.Host = host
				}
				for port := range ports {
					data.Port = port
					b, marshallErr := json.Marshal(data)
					if marshallErr != nil {
						continue
					}
					gologger.Silent().Msgf("%s\n", string(b))
				}
			} else {
				for port := range ports {
					gologger.Silent().Msgf("%s:%d\n", host, port)
				}
			}

			// file output
			if file != nil {
				if r.options.JSON {
					err = WriteJSONOutput(host, hostIP, ports, file)
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
	}
}

const bufferSize = 128

func makePrintCallback() func(stats clistats.StatisticsClient) {
	builder := &strings.Builder{}
	builder.Grow(bufferSize)

	return func(stats clistats.StatisticsClient) {
		builder.WriteRune('[')
		startedAt, _ := stats.GetStatic("startedAt")
		duration := time.Since(startedAt.(time.Time))
		builder.WriteString(clistats.FmtDuration(duration))
		builder.WriteRune(']')

		hosts, _ := stats.GetStatic("hosts")
		builder.WriteString(" | Hosts: ")
		builder.WriteString(clistats.String(hosts))

		ports, _ := stats.GetStatic("ports")
		builder.WriteString(" | Ports: ")
		builder.WriteString(clistats.String(ports))

		retries, _ := stats.GetStatic("retries")
		builder.WriteString(" | Retries: ")
		builder.WriteString(clistats.String(retries))

		packets, _ := stats.GetCounter("packets")
		total, _ := stats.GetCounter("total")

		builder.WriteString(" | PPS: ")
		builder.WriteString(clistats.String(uint64(float64(packets) / duration.Seconds())))

		builder.WriteString(" | Packets: ")
		builder.WriteString(clistats.String(packets))
		builder.WriteRune('/')
		builder.WriteString(clistats.String(total))
		builder.WriteRune(' ')
		builder.WriteRune('[')
		//nolint:gomnd // this is not a magic number
		builder.WriteString(clistats.String(uint64(float64(packets) / float64(total) * 100.0)))
		builder.WriteRune('%')
		builder.WriteRune(']')
		builder.WriteRune('\n')
		gologger.Info().Msg(builder.String())
		builder.Reset()
	}
}
