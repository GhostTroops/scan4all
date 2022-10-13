package runner

import (
	"os"
	"time"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/naabu/v2/pkg/result"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
)

// Options contains the configuration options for tuning
// the port enumeration process.
// nolint:maligned // just an option structure
type Options struct {
	Verbose        bool // Verbose flag indicates whether to show verbose output or not
	NoColor        bool // No-Color disables the colored output
	JSON           bool // JSON specifies whether to use json for output format or text file
	Silent         bool // Silent suppresses any extra text and only writes found host:port to screen
	Stdin          bool // Stdin specifies whether stdin input was given to the process
	Verify         bool // Verify is used to check if the ports found were valid using CONNECT method
	Version        bool // Version specifies if we should just show version and exit
	Ping           bool // Ping uses ping probes to discover fastest active host and discover dead hosts
	Debug          bool // Prints out debug information
	ExcludeCDN     bool // Excludes ip of knows CDN ranges for full port scan
	Nmap           bool // Invoke nmap detailed scan on results
	InterfacesList bool // InterfacesList show interfaces list

	Retries           int                 // Retries is the number of retries for the port
	Rate              int                 // Rate is the rate of port scan requests
	Timeout           int                 // Timeout is the seconds to wait for ports to respond
	WarmUpTime        int                 // WarmUpTime between scan phases
	Host              goflags.StringSlice // Host is the single host or comma-separated list of hosts to find ports for
	HostsFile         string              // HostsFile is the file containing list of hosts to find port for
	Output            string              // Output is the file to write found ports to.
	Ports             string              // Ports is the ports to use for enumeration
	PortsFile         string              // PortsFile is the file containing ports to use for enumeration
	ExcludePorts      string              // ExcludePorts is the list of ports to exclude from enumeration
	ExcludeIps        string              // Ips or cidr to be excluded from the scan
	ExcludeIpsFile    string              // File containing Ips or cidr to exclude from the scan
	TopPorts          string              // Tops ports to scan
	SourceIP          string              // SourceIP to use in TCP packets
	SourcePort        string              // Source Port to use in packets
	Interface         string              // Interface to use for TCP packets
	ConfigFile        string              // Config file contains a scan configuration
	NmapCLI           string              // Nmap command (has priority over config file)
	Threads           int                 // Internal worker threads
	EnableProgressBar bool                // Enable progress bar
	ScanAllIPS        bool                // Scan all the ips
	IPVersion         goflags.StringSlice // IP Version to use while resolving hostnames
	ScanType          string              // Scan Type
	Proxy             string              // Socks5 proxy
	ProxyAuth         string              // Socks5 proxy authentication (username:password)
	Resolvers         string              // Resolvers (comma separated or file)
	baseResolvers     []string
	OnResult          OnResultCallback // OnResult callback
	CSV               bool
	StatsInterval     int // StatsInterval is the number of seconds to display stats after
	Resume            bool
	ResumeCfg         *ResumeCfg
	Stream            bool
	Passive           bool
	OutputCDN         bool // display cdn in use
	HealthCheck       bool
	HostDiscovery     bool // Enable Host Discovery
	TcpSynPingProbes  goflags.StringSlice
	TcpAckPingProbes  goflags.StringSlice
	// UdpPingProbes               goflags.StringSlice - planned
	// STcpInitPingProbes          goflags.StringSlice - planned
	IcmpEchoRequestProbe        bool
	IcmpTimestampRequestProbe   bool
	IcmpAddressMaskRequestProbe bool
	// IpProtocolPingProbes        goflags.StringSlice - planned
	ArpPing                   bool
	IPv6NeighborDiscoveryPing bool
	// HostDiscoveryIgnoreRST      bool - planned
	InputReadTimeout time.Duration
	DisableStdin     bool
}

// OnResultCallback (hostResult)
type OnResultCallback func(*result.HostResult)

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Naabu is a port scanning tool written in Go that allows you to enumerate open ports for hosts in a fast and reliable manner.`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&options.Host, "host", "", nil, "hosts to scan ports for (comma-separated)", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.HostsFile, "l", "list", "", "list of hosts to scan ports (file)"),
		flagSet.StringVarP(&options.ExcludeIps, "eh", "exclude-hosts", "", "hosts to exclude from the scan (comma-separated)"),
		flagSet.StringVarP(&options.ExcludeIpsFile, "ef", "exclude-file", "", "list of hosts to exclude from scan (file)"),
	)

	flagSet.CreateGroup("port", "Port",
		flagSet.StringVarP(&options.Ports, "p", "port", "", "ports to scan (80,443, 100-200)"),
		flagSet.StringVarP(&options.TopPorts, "tp", "top-ports", "", "top ports to scan (default 100)"),
		flagSet.StringVarP(&options.ExcludePorts, "ep", "exclude-ports", "", "ports to exclude from scan (comma-separated)"),
		flagSet.StringVarP(&options.PortsFile, "pf", "ports-file", "", "list of ports to scan (file)"),
		flagSet.BoolVarP(&options.ExcludeCDN, "ec", "exclude-cdn", false, "skip full port scans for CDN's (only checks for 80,443)"),
		flagSet.BoolVarP(&options.OutputCDN, "cdn", "display-cdn", false, "display cdn in use"),
	)

	flagSet.CreateGroup("rate-limit", "Rate-limit",
		flagSet.IntVar(&options.Threads, "c", 25, "general internal worker threads"),
		flagSet.IntVar(&options.Rate, "rate", DefaultRateSynScan, "packets to send per second"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.Output, "output", "o", "", "file to write output to (optional)"),
		flagSet.BoolVar(&options.JSON, "json", false, "write output in JSON lines format"),
		flagSet.BoolVar(&options.CSV, "csv", false, "write output in csv format"),
	)

	flagSet.CreateGroup("config", "Configuration",
		flagSet.BoolVarP(&options.ScanAllIPS, "sa", "scan-all-ips", false, "scan all the IP's associated with DNS record"),
		flagSet.StringSliceVarP(&options.IPVersion, "iv", "ip-version", nil, "ip version to scan of hostname (4,6) - (default 4)", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.ScanType, "s", "scan-type", SynScan, "type of port scan (SYN/CONNECT)"),
		flagSet.StringVar(&options.SourceIP, "source-ip", "", "source ip and port (x.x.x.x:yyy)"),
		flagSet.BoolVarP(&options.InterfacesList, "il", "interface-list", false, "list available interfaces and public ip"),
		flagSet.StringVarP(&options.Interface, "i", "interface", "", "network Interface to use for port scan"),
		flagSet.BoolVar(&options.Nmap, "nmap", false, "invoke nmap scan on targets (nmap must be installed) - Deprecated"),
		flagSet.StringVar(&options.NmapCLI, "nmap-cli", "", "nmap command to run on found results (example: -nmap-cli 'nmap -sV')"),
		flagSet.StringVar(&options.Resolvers, "r", "", "list of custom resolver dns resolution (comma separated or from file)"),
		flagSet.StringVar(&options.Proxy, "proxy", "", "socks5 proxy (ip[:port] / fqdn[:port]"),
		flagSet.StringVar(&options.ProxyAuth, "proxy-auth", "", "socks5 proxy authentication (username:password)"),
		flagSet.BoolVar(&options.Resume, "resume", false, "resume scan using resume.cfg"),
		flagSet.BoolVar(&options.Stream, "stream", false, "stream mode (disables resume, nmap, verify, retries, shuffling, etc)"),
		flagSet.BoolVar(&options.Passive, "passive", false, "display passive open ports using shodan internetdb api"),
		flagSet.DurationVarP(&options.InputReadTimeout, "input-read-timeout", "irt", time.Duration(3*time.Minute), "timeout on input read"),
		flagSet.BoolVar(&options.DisableStdin, "no-stdin", false, "Disable Stdin processing"),
	)

	flagSet.CreateGroup("host-discovery", "Host-Discovery",
		flagSet.BoolVarP(&options.HostDiscovery, "host-discovery", "sn", false, "Run Host Discovery scan"),
		flagSet.StringSliceVarP(&options.TcpSynPingProbes, "probe-tcp-syn", "ps", nil, "TCP SYN Ping (host discovery needs to be enabled)", goflags.StringSliceOptions),
		flagSet.StringSliceVarP(&options.TcpAckPingProbes, "probe-tcp-ack", "pa", nil, "TCP ACK Ping (host discovery needs to be enabled)", goflags.StringSliceOptions),
		flagSet.BoolVarP(&options.IcmpEchoRequestProbe, "probe-icmp-echo", "pe", false, "ICMP echo request Ping (host discovery needs to be enabled)"),
		flagSet.BoolVarP(&options.IcmpTimestampRequestProbe, "probe-icmp-timestamp", "pp", false, "ICMP timestamp request Ping (host discovery needs to be enabled)"),
		flagSet.BoolVarP(&options.IcmpAddressMaskRequestProbe, "probe-icmp-address-mask", "pm", false, "ICMP address mask request Ping (host discovery needs to be enabled)"),
		flagSet.BoolVarP(&options.ArpPing, "arp-ping", "arp", false, "ARP ping (host discovery needs to be enabled)"),
		flagSet.BoolVarP(&options.IPv6NeighborDiscoveryPing, "nd-ping", "nd", false, "IPv6 Neighbor Discovery (host discovery needs to be enabled)"),
		// The following flags are left as placeholder
		// flagSet.StringSliceVarP(&options.IpProtocolPingProbes, "probe-ip-protocol", "po", []string{}, "IP Protocol Ping"),
		// flagSet.StringSliceVarP(&options.UdpPingProbes, "probe-udp", "pu", []string{}, "UDP Ping"),
		// flagSet.StringSliceVarP(&options.STcpInitPingProbes, "probe-stcp-init", "py", []string{}, "SCTP INIT Ping"),
		// flagSet.BoolVarP(&options.HostDiscoveryIgnoreRST, "discovery-ignore-rst", "irst", false, "Ignore RST packets during host discovery"),
	)

	flagSet.CreateGroup("optimization", "Optimization",
		flagSet.IntVar(&options.Retries, "retries", DefaultRetriesSynScan, "number of retries for the port scan"),
		flagSet.IntVar(&options.Timeout, "timeout", DefaultPortTimeoutSynScan, "millisecond to wait before timing out"),
		flagSet.IntVar(&options.WarmUpTime, "warm-up-time", 2, "time in seconds between scan phases"),
		flagSet.BoolVar(&options.Ping, "ping", false, "ping probes for verification of host"),
		flagSet.BoolVar(&options.Verify, "verify", false, "validate the ports again with TCP verification"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVarP(&options.HealthCheck, "hc", "health-check", false, "run diagnostic check up"),
		flagSet.BoolVar(&options.Debug, "debug", false, "display debugging information"),
		flagSet.BoolVarP(&options.Verbose, "v", "verbose", false, "display verbose output"),
		flagSet.BoolVarP(&options.NoColor, "nc", "no-color", false, "disable colors in CLI output"),
		flagSet.BoolVar(&options.Silent, "silent", false, "display only results in output"),
		flagSet.BoolVar(&options.Version, "version", false, "display version of naabu"),
		flagSet.BoolVar(&options.EnableProgressBar, "stats", false, "display stats of the running scan"),
		flagSet.IntVarP(&options.StatsInterval, "stats-interval", "si", DefautStatsInterval, "number of seconds to wait between showing a statistics update"),
	)

	_ = flagSet.Parse()

	if options.HealthCheck {
		gologger.Print().Msgf("%s\n", DoHealthCheck(options))
		os.Exit(0)
	}

	// Check if stdin pipe was given
	options.Stdin = !options.DisableStdin && fileutil.HasStdin()

	// configure host discovery if necessary
	options.configureHostDiscovery()

	// Read the inputs and configure the logging
	options.configureOutput()
	options.ResumeCfg = NewResumeCfg()
	if options.ShouldLoadResume() {
		if err := options.ResumeCfg.ConfigureResume(); err != nil {
			gologger.Fatal().Msgf("%s\n", err)
		}
	}
	// Show the user the banner
	showBanner()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", Version)
		os.Exit(0)
	}

	// Show network configuration and exit if the user requested it
	if options.InterfacesList {
		err := showNetworkInterfaces()
		if err != nil {
			gologger.Error().Msgf("Could not get network interfaces: %s\n", err)
		}
		os.Exit(0)
	}

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	err := options.validateOptions()
	if err != nil {
		gologger.Fatal().Msgf("Program exiting: %s\n", err)
	}

	return options
}

// ShouldLoadResume resume file
func (options *Options) ShouldLoadResume() bool {
	return options.Resume && fileutil.FileExists(DefaultResumeFilePath())
}
