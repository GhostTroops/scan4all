// Package nmap provides idiomatic `nmap` bindings for go developers.
package nmap

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ScanRunner represents something that can run a scan.
type ScanRunner interface {
	Run() (result *Run, warnings []string, err error)
}

// Scanner represents an Nmap scanner.
type Scanner struct {
	cmd *exec.Cmd

	args       []string
	binaryPath string
	ctx        context.Context

	portFilter func(Port) bool
	hostFilter func(Host) bool

	stderr, stdout bufio.Scanner
}

// NewScanner creates a new Scanner, and can take options to apply to the scanner.
func NewScanner(options ...func(*Scanner)) (*Scanner, error) {
	scanner := &Scanner{}

	for _, option := range options {
		option(scanner)
	}

	if scanner.binaryPath == "" {
		var err error
		scanner.binaryPath, err = exec.LookPath("nmap")
		if err != nil {
			return nil, ErrNmapNotInstalled
		}
	}

	if scanner.ctx == nil {
		scanner.ctx = context.Background()
	}

	return scanner, nil
}

// Run runs nmap synchronously and returns the result of the scan.
func (s *Scanner) Run() (result *Run, warnings []string, err error) {
	var stdout, stderr bytes.Buffer

	// Enable XML output
	s.args = append(s.args, "-oX")

	// Get XML output in stdout instead of writing it in a file
	s.args = append(s.args, "-")

	// Prepare nmap process
	cmd := exec.Command(s.binaryPath, s.args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Run nmap process
	err = cmd.Start()
	if err != nil {
		return nil, warnings, err
	}

	// Make a goroutine to notify the select when the scan is done.
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// Wait for nmap process or timeout
	select {
	case <-s.ctx.Done():

		// Context was done before the scan was finished.
		// The process is killed and a timeout error is returned.
		_ = cmd.Process.Kill()

		return nil, warnings, ErrScanTimeout
	case <-done:

		// Process nmap stderr output containing none-critical errors and warnings
		// Everyone needs to check whether one or some of these warnings is a hard issue in their use case
		if stderr.Len() > 0 {
			warnings = strings.Split(strings.Trim(stderr.String(), "\n"), "\n")
		}

		// Parse nmap xml output. Usually nmap always returns valid XML, even if there is a scan error.
		// Potentially available warnings are returned too, but probably not the reason for a broken XML.
		result, err := Parse(stdout.Bytes())
		if err != nil {
			warnings = append(warnings, err.Error()) // Append parsing error to warnings for those who are interested.
			return nil, warnings, ErrParseOutput
		}

		// Critical scan errors are reflected in the XML.
		if result != nil && len(result.Stats.Finished.ErrorMsg) > 0 {
			switch {
			case strings.Contains(result.Stats.Finished.ErrorMsg, "Error resolving name"):
				return result, warnings, ErrResolveName
			// TODO: Add cases for other known errors we might want to guard.
			default:
				return result, warnings, fmt.Errorf(result.Stats.Finished.ErrorMsg)
			}
		}

		// Call filters if they are set.
		if s.portFilter != nil {
			result = choosePorts(result, s.portFilter)
		}
		if s.hostFilter != nil {
			result = chooseHosts(result, s.hostFilter)
		}

		// Return result, optional warnings but no error
		return result, warnings, nil
	}
}

// RunAsync runs nmap asynchronously and returns error.
// TODO: RunAsync should return warnings as well.
func (s *Scanner) RunAsync() error {
	// Enable XML output.
	s.args = append(s.args, "-oX")

	// Get XML output in stdout instead of writing it in a file.
	s.args = append(s.args, "-")
	s.cmd = exec.Command(s.binaryPath, s.args...)

	stderr, err := s.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("unable to get error output from asynchronous nmap run: %v", err)
	}

	stdout, err := s.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("unable to get standard output from asynchronous nmap run: %v", err)
	}

	s.stdout = *bufio.NewScanner(stdout)
	s.stderr = *bufio.NewScanner(stderr)

	if err := s.cmd.Start(); err != nil {
		return fmt.Errorf("unable to execute asynchronous nmap run: %v", err)
	}

	go func() {
		<-s.ctx.Done()
		_ = s.cmd.Process.Kill()
	}()

	return nil
}

// Wait waits for the cmd to finish and returns error.
func (s *Scanner) Wait() error {
	return s.cmd.Wait()
}

// GetStdout returns stdout variable for scanner.
func (s *Scanner) GetStdout() bufio.Scanner {
	return s.stdout
}

//  GetStdout returns stderr variable for scanner.
func (s *Scanner) GetStderr() bufio.Scanner {
	return s.stderr
}

func chooseHosts(result *Run, filter func(Host) bool) *Run {
	var filteredHosts []Host

	for _, host := range result.Hosts {
		if filter(host) {
			filteredHosts = append(filteredHosts, host)
		}
	}

	result.Hosts = filteredHosts

	return result
}

func choosePorts(result *Run, filter func(Port) bool) *Run {
	for idx := range result.Hosts {
		var filteredPorts []Port

		for _, port := range result.Hosts[idx].Ports {
			if filter(port) {
				filteredPorts = append(filteredPorts, port)
			}
		}

		result.Hosts[idx].Ports = filteredPorts
	}

	return result
}

// WithContext adds a context to a scanner, to make it cancellable and able to timeout.
func WithContext(ctx context.Context) func(*Scanner) {
	return func(s *Scanner) {
		s.ctx = ctx
	}
}

// WithBinaryPath sets the nmap binary path for a scanner.
func WithBinaryPath(binaryPath string) func(*Scanner) {
	return func(s *Scanner) {
		s.binaryPath = binaryPath
	}
}

// WithCustomArguments sets custom arguments to give to the nmap binary.
// There should be no reason to use this, unless you are using a custom build
// of nmap or that this repository isn't up to date with the latest options
// of the official nmap release.
// You can use this as a quick way to paste an nmap command into your go code,
// but remember that the whole purpose of this repository is to be idiomatic,
// provide type checking, enums for the values that can be passed, etc.
func WithCustomArguments(args ...string) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, args...)
	}
}

// WithFilterPort allows to set a custom function to filter out ports that
// don't fulfill a given condition. When the given function returns true,
// the port is kept, otherwise it is removed from the result. Can be used
// along with WithFilterHost.
func WithFilterPort(portFilter func(Port) bool) func(*Scanner) {
	return func(s *Scanner) {
		s.portFilter = portFilter
	}
}

// WithFilterHost allows to set a custom function to filter out hosts that
// don't fulfill a given condition. When the given function returns true,
// the host is kept, otherwise it is removed from the result. Can be used
// along with WithFilterPort.
func WithFilterHost(hostFilter func(Host) bool) func(*Scanner) {
	return func(s *Scanner) {
		s.hostFilter = hostFilter
	}
}

/*** Target specification ***/

// WithTargets sets the target of a scanner.
func WithTargets(targets ...string) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, targets...)
	}
}

// WithTargetExclusion sets the excluded targets of a scanner.
func WithTargetExclusion(target string) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--exclude")
		s.args = append(s.args, target)
	}
}

// WithTargetInput sets the input file name to set the targets.
func WithTargetInput(inputFileName string) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-iL")
		s.args = append(s.args, inputFileName)
	}
}

// WithTargetExclusionInput sets the input file name to set the target exclusions.
func WithTargetExclusionInput(inputFileName string) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--excludefile")
		s.args = append(s.args, inputFileName)
	}
}

// WithRandomTargets sets the amount of targets to randomly choose from the targets.
func WithRandomTargets(randomTargets int) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-iR")
		s.args = append(s.args, fmt.Sprint(randomTargets))
	}
}

/*** Host discovery ***/

// WithListScan sets the discovery mode to simply list the targets to scan and not scan them.
func WithListScan() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-sL")
	}
}

// WithPingScan sets the discovery mode to simply ping the targets to scan and not scan them.
func WithPingScan() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-sn")
	}
}

// WithSkipHostDiscovery diables host discovery and considers all hosts as online.
func WithSkipHostDiscovery() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-Pn")
	}
}

// WithSYNDiscovery sets the discovery mode to use SYN packets.
// If the portList argument is empty, this will enable SYN discovery
// for all ports. Otherwise, it will be only for the specified ports.
func WithSYNDiscovery(ports ...string) func(*Scanner) {
	portList := strings.Join(ports, ",")

	return func(s *Scanner) {
		s.args = append(s.args, fmt.Sprintf("-PS%s", portList))
	}
}

// WithACKDiscovery sets the discovery mode to use ACK packets.
// If the portList argument is empty, this will enable ACK discovery
// for all ports. Otherwise, it will be only for the specified ports.
func WithACKDiscovery(ports ...string) func(*Scanner) {
	portList := strings.Join(ports, ",")

	return func(s *Scanner) {
		s.args = append(s.args, fmt.Sprintf("-PA%s", portList))
	}
}

// WithUDPDiscovery sets the discovery mode to use UDP packets.
// If the portList argument is empty, this will enable UDP discovery
// for all ports. Otherwise, it will be only for the specified ports.
func WithUDPDiscovery(ports ...string) func(*Scanner) {
	portList := strings.Join(ports, ",")

	return func(s *Scanner) {
		s.args = append(s.args, fmt.Sprintf("-PU%s", portList))
	}
}

// WithSCTPDiscovery sets the discovery mode to use SCTP packets
// containing a minimal INIT chunk.
// If the portList argument is empty, this will enable SCTP discovery
// for all ports. Otherwise, it will be only for the specified ports.
// Warning: on Unix, only the privileged user root is generally
// able to send and receive raw SCTP packets.
func WithSCTPDiscovery(ports ...string) func(*Scanner) {
	portList := strings.Join(ports, ",")

	return func(s *Scanner) {
		s.args = append(s.args, fmt.Sprintf("-PY%s", portList))
	}
}

// WithICMPEchoDiscovery sets the discovery mode to use an ICMP type 8
// packet (an echo request), like the standard packets sent by the ping
// command.
// Many hosts and firewalls block these packets, so this is usually not
// the best for exploring networks.
func WithICMPEchoDiscovery() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-PE")
	}
}

// WithICMPTimestampDiscovery sets the discovery mode to use an ICMP type 13
// packet (a timestamp request).
// This query can be valuable when administrators specifically block echo
// request packets while forgetting that other ICMP queries can be used
// for the same purpose.
func WithICMPTimestampDiscovery() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-PP")
	}
}

// WithICMPNetMaskDiscovery sets the discovery mode to use an ICMP type 17
// packet (an address mask request).
// This query can be valuable when administrators specifically block echo
// request packets while forgetting that other ICMP queries can be used
// for the same purpose.
func WithICMPNetMaskDiscovery() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-PM")
	}
}

// WithIPProtocolPingDiscovery sets the discovery mode to use the IP
// protocol ping.
// If no protocols are specified, the default is to send multiple IP
// packets for ICMP (protocol 1), IGMP (protocol 2), and IP-in-IP
// (protocol 4).
func WithIPProtocolPingDiscovery(protocols ...string) func(*Scanner) {
	protocolList := strings.Join(protocols, ",")

	return func(s *Scanner) {
		s.args = append(s.args, fmt.Sprintf("-PO%s", protocolList))
	}
}

// WithDisabledDNSResolution disables DNS resolution in the discovery
// step of the nmap scan.
func WithDisabledDNSResolution() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-n")
	}
}

// WithForcedDNSResolution enforces DNS resolution in the discovery
// step of the nmap scan.
func WithForcedDNSResolution() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-R")
	}
}

// WithCustomDNSServers sets custom DNS servers for the scan.
// List format: dns1[,dns2],...
func WithCustomDNSServers(dnsServers ...string) func(*Scanner) {
	dnsList := strings.Join(dnsServers, ",")

	return func(s *Scanner) {
		s.args = append(s.args, "--dns-servers")
		s.args = append(s.args, dnsList)
	}
}

// WithSystemDNS sets the scanner's DNS to the system's DNS.
func WithSystemDNS() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--system-dns")
	}
}

// WithTraceRoute enables the tracing of the hop path to each host.
func WithTraceRoute() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--traceroute")
	}
}

/*** Scan techniques ***/

// WithSYNScan sets the scan technique to use SYN packets over TCP.
// This is the default method, as it is fast, stealthy and not
// hampered by restrictive firewalls.
func WithSYNScan() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-sS")
	}
}

// WithConnectScan sets the scan technique to use TCP connections.
// This is the default method used when a user does not have raw
// packet privileges. Target machines are likely to log these
// connections.
func WithConnectScan() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-sT")
	}
}

// WithACKScan sets the scan technique to use ACK packets over TCP.
// This scan is unable to determine if a port is open.
// When scanning unfiltered systems, open and closed ports will both
// return a RST packet.
// Nmap then labels them as unfiltered, meaning that they are reachable
// by the ACK packet, but whether they are open or closed is undetermined.
func WithACKScan() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-sA")
	}
}

// WithWindowScan sets the scan technique to use ACK packets over TCP and
// examining the TCP window field of the RST packets returned.
// Window scan is exactly the same as ACK scan except that it exploits
// an implementation detail of certain systems to differentiate open ports
// from closed ones, rather than always printing unfiltered when a RST
// is returned.
func WithWindowScan() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-sW")
	}
}

// WithMaimonScan sends the same packets as NULL, FIN, and Xmas scans,
// except that the probe is FIN/ACK. Many BSD-derived systems will drop
// these packets if the port is open.
func WithMaimonScan() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-sM")
	}
}

// WithUDPScan sets the scan technique to use UDP packets.
// It can be combined with a TCP scan type such as SYN scan
// to check both protocols during the same run.
// UDP scanning is generally slower than TCP, but should not
// be ignored.
func WithUDPScan() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-sU")
	}
}

// WithTCPNullScan sets the scan technique to use TCP null packets.
// (TCP flag header is 0). This scan method can be used to exploit
// a loophole in the TCP RFC.
// If an RST packet is received, the port is considered closed,
// while no response means it is open|filtered.
func WithTCPNullScan() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-sN")
	}
}

// WithTCPFINScan sets the scan technique to use TCP packets with
// the FIN flag set.
// This scan method can be used to exploit a loophole in the TCP RFC.
// If an RST packet is received, the port is considered closed,
// while no response means it is open|filtered.
func WithTCPFINScan() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-sF")
	}
}

// WithTCPXmasScan sets the scan technique to use TCP packets with
// the FIN, PSH and URG flags set.
// This scan method can be used to exploit a loophole in the TCP RFC.
// If an RST packet is received, the port is considered closed,
// while no response means it is open|filtered.
func WithTCPXmasScan() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-sX")
	}
}

// TCPFlag represents a TCP flag.
type TCPFlag int

// Flag enumerations.
const (
	FlagNULL TCPFlag = 0
	FlagFIN  TCPFlag = 1
	FlagSYN  TCPFlag = 2
	FlagRST  TCPFlag = 4
	FlagPSH  TCPFlag = 8
	FlagACK  TCPFlag = 16
	FlagURG  TCPFlag = 32
	FlagECE  TCPFlag = 64
	FlagCWR  TCPFlag = 128
	FlagNS   TCPFlag = 256
)

// WithTCPScanFlags sets the scan technique to use custom TCP flags.
func WithTCPScanFlags(flags ...TCPFlag) func(*Scanner) {
	var total int
	for _, flag := range flags {
		total += int(flag)
	}

	return func(s *Scanner) {
		s.args = append(s.args, "--scanflags")
		s.args = append(s.args, fmt.Sprintf("%x", total))
	}
}

// WithIdleScan sets the scan technique to use a zombie host to
// allow for a truly blind TCP port scan of the target.
// Besides being extraordinarily stealthy (due to its blind nature),
// this scan type permits mapping out IP-based trust relationships
// between machines.
func WithIdleScan(zombieHost string, probePort int) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-sI")

		if probePort != 0 {
			s.args = append(s.args, fmt.Sprintf("%s:%d", zombieHost, probePort))
		} else {
			s.args = append(s.args, zombieHost)
		}
	}
}

// WithSCTPInitScan sets the scan technique to use SCTP packets
// containing an INIT chunk.
// It can be performed quickly, scanning thousands of ports per
// second on a fast network not hampered by restrictive firewalls.
// Like SYN scan, INIT scan is relatively unobtrusive and stealthy,
// since it never completes SCTP associations.
func WithSCTPInitScan() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-sY")
	}
}

// WithSCTPCookieEchoScan sets the scan technique to use SCTP packets
// containing a COOKIE-ECHO chunk.
// The advantage of this scan type is that it is not as obvious a port
// scan than an INIT scan. Also, there may be non-stateful firewall
// rulesets blocking INIT chunks, but not COOKIE ECHO chunks.
func WithSCTPCookieEchoScan() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-sZ")
	}
}

// WithIPProtocolScan sets the scan technique to use the IP protocol.
// IP protocol scan allows you to determine which IP protocols
// (TCP, ICMP, IGMP, etc.) are supported by target machines. This isn't
// technically a port scan, since it cycles through IP protocol numbers
// rather than TCP or UDP port numbers.
func WithIPProtocolScan() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-sO")
	}
}

// WithFTPBounceScan sets the scan technique to use the an FTP relay host.
// It takes an argument of the form "<username>:<password>@<server>:<port>. <Server>".
// You may omit <username>:<password>, in which case anonymous login credentials
// (user: anonymous password:-wwwuser@) are used.
// The port number (and preceding colon) may be omitted as well, in which case the
// default FTP port (21) on <server> is used.
func WithFTPBounceScan(FTPRelayHost string) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-b")
		s.args = append(s.args, FTPRelayHost)
	}
}

/*** Port specification and scan order ***/

// WithPorts sets the ports which the scanner should scan on each host.
func WithPorts(ports ...string) func(*Scanner) {
	portList := strings.Join(ports, ",")

	return func(s *Scanner) {
		s.args = append(s.args, "-p")
		s.args = append(s.args, portList)
	}
}

// WithPortExclusions sets the ports that the scanner should not scan on each host.
func WithPortExclusions(ports ...string) func(*Scanner) {
	portList := strings.Join(ports, ",")

	return func(s *Scanner) {
		s.args = append(s.args, "--exclude-ports")
		s.args = append(s.args, portList)
	}
}

// WithFastMode makes the scan faster by scanning fewer ports than the default scan.
func WithFastMode() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-F")
	}
}

// WithConsecutivePortScanning makes the scan go through ports consecutively instead of
// picking them out randomly.
func WithConsecutivePortScanning() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-r")
	}
}

// WithMostCommonPorts sets the scanner to go through the provided number of most
// common ports.
func WithMostCommonPorts(number int) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--top-ports")
		s.args = append(s.args, fmt.Sprint(number))
	}
}

// WithPortRatio sets the scanner to go the ports more common than the given ratio.
// Ratio must be a float between 0 and 1.
func WithPortRatio(ratio float32) func(*Scanner) {
	return func(s *Scanner) {
		if ratio < 0 || ratio > 1 {
			panic("value given to nmap.WithPortRatio() should be between 0 and 1")
		}

		s.args = append(s.args, "--port-ratio")
		s.args = append(s.args, fmt.Sprintf("%.1f", ratio))
	}
}

/*** Service/Version detection ***/

// WithServiceInfo enables the probing of open ports to determine service and version
// info.
func WithServiceInfo() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-sV")
	}
}

// WithVersionIntensity sets the level of intensity with which nmap should
// probe the open ports to get version information.
// Intensity should be a value between 0 (light) and 9 (try all probes). The
// default value is 7.
func WithVersionIntensity(intensity int16) func(*Scanner) {
	return func(s *Scanner) {
		if intensity < 0 || intensity > 9 {
			panic("value given to nmap.WithVersionIntensity() should be between 0 and 9")
		}

		s.args = append(s.args, "--version-intensity")
		s.args = append(s.args, fmt.Sprint(intensity))
	}
}

// WithVersionLight sets the level of intensity with which nmap should probe the
// open ports to get version information to 2. This will make version scanning much
// faster, but slightly less likely to identify services.
func WithVersionLight() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--version-light")
	}
}

// WithVersionAll sets the level of intensity with which nmap should probe the
// open ports to get version information to 9. This will ensure that every single
// probe is attempted against each port.
func WithVersionAll() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--version-all")
	}
}

// WithVersionTrace causes Nmap to print out extensive debugging info about what
// version scanning is doing.
// TODO: See how this works along with XML output.
func WithVersionTrace() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--version-trace")
	}
}

/*** Script scan ***/

// WithDefaultScript sets the scanner to perform a script scan using the default
// set of scripts. It is equivalent to --script=default. Some of the scripts in
// this category are considered intrusive and should not be run against a target
// network without permission.
func WithDefaultScript() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-sC")
	}
}

// WithScripts sets the scanner to perform a script scan using the enumerated
// scripts, script directories and script categories.
func WithScripts(scripts ...string) func(*Scanner) {
	scriptList := strings.Join(scripts, ",")

	return func(s *Scanner) {
		s.args = append(s.args, fmt.Sprintf("--script=%s", scriptList))
	}
}

// WithScriptArguments provides arguments for scripts. If a value is the empty string, the key will be used as a flag.
func WithScriptArguments(arguments map[string]string) func(*Scanner) {
	var argList string

	// Properly format the argument list from the map.
	// Complex example:
	// user=foo,pass=",{}=bar",whois={whodb=nofollow+ripe},xmpp-info.server_name=localhost,vulns.showall
	for key, value := range arguments {
		str := ""
		if value == "" {
			str = key
		} else {
			str = fmt.Sprintf("%s=%s", key, value)
		}

		argList = strings.Join([]string{argList, str}, ",")
	}

	argList = strings.TrimLeft(argList, ",")

	return func(s *Scanner) {
		s.args = append(s.args, fmt.Sprintf("--script-args=%s", argList))
	}
}

// WithScriptArgumentsFile provides arguments for scripts from a file.
func WithScriptArgumentsFile(inputFilePath string) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, fmt.Sprintf("--script-args-file=%s", inputFilePath))
	}
}

// WithScriptTrace makes the scripts show all data sent and received.
func WithScriptTrace() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--script-trace")
	}
}

// WithScriptUpdateDB updates the script database.
func WithScriptUpdateDB() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--script-updatedb")
	}
}

/*** OS Detection ***/

// WithOSDetection enables OS detection.
func WithOSDetection() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-O")
	}
}

// WithOSScanLimit sets the scanner to not even try OS detection against
// hosts that do have at least one open TCP port, as it is unlikely to be effective.
// This can save substantial time, particularly on -Pn scans against many hosts.
// It only matters when OS detection is requested with -O or -A.
func WithOSScanLimit() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--osscan-limit")
	}
}

// WithOSScanGuess makes nmap attempt to guess the OS more aggressively.
func WithOSScanGuess() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--osscan-guess")
	}
}

/*** Timing and performance ***/

// Timing represents a timing template for nmap.
// These are meant to be used with the WithTimingTemplate method.
type Timing int16

const (
	// TimingSlowest also called paranoiac		NO PARALLELISM | 5min  timeout | 100ms to 10s    round-trip time timeout	| 5mn   scan delay
	TimingSlowest Timing = 0
	// TimingSneaky 							NO PARALLELISM | 15sec timeout | 100ms to 10s    round-trip time timeout	| 15s   scan delay
	TimingSneaky Timing = 1
	// TimingPolite 							NO PARALLELISM | 1sec  timeout | 100ms to 10s    round-trip time timeout	| 400ms scan delay
	TimingPolite Timing = 2
	// TimingNormal 							PARALLELISM	   | 1sec  timeout | 100ms to 10s    round-trip time timeout	| 0s    scan delay
	TimingNormal Timing = 3
	// TimingAggressive 						PARALLELISM	   | 500ms timeout | 100ms to 1250ms round-trip time timeout	| 0s    scan delay
	TimingAggressive Timing = 4
	// TimingFastest also called insane			PARALLELISM	   | 250ms timeout |  50ms to 300ms  round-trip time timeout	| 0s    scan delay
	TimingFastest Timing = 5
)

// WithTimingTemplate sets the timing template for nmap.
func WithTimingTemplate(timing Timing) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, fmt.Sprintf("-T%d", timing))
	}
}

// WithStatsEvery periodically prints a timing status message after each interval of time.
func WithStatsEvery(interval string) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--stats-every")
		s.args = append(s.args, interval)
	}
}

// WithMinHostgroup sets the minimal parallel host scan group size.
func WithMinHostgroup(size int) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--min-hostgroup")
		s.args = append(s.args, fmt.Sprint(size))
	}
}

// WithMaxHostgroup sets the maximal parallel host scan group size.
func WithMaxHostgroup(size int) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--max-hostgroup")
		s.args = append(s.args, fmt.Sprint(size))
	}
}

// WithMinParallelism sets the minimal number of parallel probes.
func WithMinParallelism(probes int) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--min-parallelism")
		s.args = append(s.args, fmt.Sprint(probes))
	}
}

// WithMaxParallelism sets the maximal number of parallel probes.
func WithMaxParallelism(probes int) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--max-parallelism")
		s.args = append(s.args, fmt.Sprint(probes))
	}
}

// WithMinRTTTimeout sets the minimal probe round trip time.
func WithMinRTTTimeout(roundTripTime time.Duration) func(*Scanner) {
	milliseconds := roundTripTime.Round(time.Nanosecond).Nanoseconds() / 1000000

	return func(s *Scanner) {
		s.args = append(s.args, "--min-rtt-timeout")
		s.args = append(s.args, fmt.Sprintf("%dms", int(milliseconds)))
	}
}

// WithMaxRTTTimeout sets the maximal probe round trip time.
func WithMaxRTTTimeout(roundTripTime time.Duration) func(*Scanner) {
	milliseconds := roundTripTime.Round(time.Nanosecond).Nanoseconds() / 1000000

	return func(s *Scanner) {
		s.args = append(s.args, "--max-rtt-timeout")
		s.args = append(s.args, fmt.Sprintf("%dms", int(milliseconds)))
	}
}

// WithInitialRTTTimeout sets the initial probe round trip time.
func WithInitialRTTTimeout(roundTripTime time.Duration) func(*Scanner) {
	milliseconds := roundTripTime.Round(time.Nanosecond).Nanoseconds() / 1000000

	return func(s *Scanner) {
		s.args = append(s.args, "--initial-rtt-timeout")
		s.args = append(s.args, fmt.Sprintf("%dms", int(milliseconds)))
	}
}

// WithMaxRetries sets the maximal number of port scan probe retransmissions.
func WithMaxRetries(tries int) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--max-retries")
		s.args = append(s.args, fmt.Sprint(tries))
	}
}

// WithHostTimeout sets the time after which nmap should give up on a target host.
func WithHostTimeout(timeout time.Duration) func(*Scanner) {
	milliseconds := timeout.Round(time.Nanosecond).Nanoseconds() / 1000000

	return func(s *Scanner) {
		s.args = append(s.args, "--host-timeout")
		s.args = append(s.args, fmt.Sprintf("%dms", int(milliseconds)))
	}
}

// WithScanDelay sets the minimum time to wait between each probe sent to a host.
func WithScanDelay(timeout time.Duration) func(*Scanner) {
	milliseconds := timeout.Round(time.Nanosecond).Nanoseconds() / 1000000

	return func(s *Scanner) {
		s.args = append(s.args, "--scan-delay")
		s.args = append(s.args, fmt.Sprintf("%dms", int(milliseconds)))
	}
}

// WithMaxScanDelay sets the maximum time to wait between each probe sent to a host.
func WithMaxScanDelay(timeout time.Duration) func(*Scanner) {
	milliseconds := timeout.Round(time.Nanosecond).Nanoseconds() / 1000000

	return func(s *Scanner) {
		s.args = append(s.args, "--max-scan-delay")
		s.args = append(s.args, fmt.Sprintf("%dms", int(milliseconds)))
	}
}

// WithMinRate sets the minimal number of packets sent per second.
func WithMinRate(packetsPerSecond int) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--min-rate")
		s.args = append(s.args, fmt.Sprint(packetsPerSecond))
	}
}

// WithMaxRate sets the maximal number of packets sent per second.
func WithMaxRate(packetsPerSecond int) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--max-rate")
		s.args = append(s.args, fmt.Sprint(packetsPerSecond))
	}
}

/*** Firewalls/IDS evasion and spoofing ***/

// WithFragmentPackets enables the use of tiny fragmented IP packets in order to
// split up the TCP header over several packets to make it harder for packet
// filters, intrusion detection systems, and other annoyances to detect what
// you are doing.
// Some programs have trouble handling these tiny packets.
func WithFragmentPackets() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-f")
	}
}

// WithMTU allows you to specify your own offset size for fragmenting IP packets.
// Using fragmented packets allows to split up the TCP header over several packets
// to make it harder for packet filters, intrusion detection systems, and other
// annoyances to detect what you are doing.
// Some programs have trouble handling these tiny packets.
func WithMTU(offset int) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--mtu")
		s.args = append(s.args, fmt.Sprint(offset))
	}
}

// WithDecoys causes a decoy scan to be performed, which makes it appear to the
// remote host that the host(s) you specify as decoys are scanning the target
// network too. Thus their IDS might report 5–10 port scans from unique IP
// addresses, but they won't know which IP was scanning them and which were
// innocent decoys.
// While this can be defeated through router path tracing, response-dropping,
// and other active mechanisms, it is generally an effective technique for
// hiding your IP address.
// You can optionally use ME as one of the decoys to represent the position
// for your real IP address.
// If you put ME in the sixth position or later, some common port scan
// detectors are unlikely to show your IP address at all.
func WithDecoys(decoys ...string) func(*Scanner) {
	decoyList := strings.Join(decoys, ",")

	return func(s *Scanner) {
		s.args = append(s.args, "-D")
		s.args = append(s.args, decoyList)
	}
}

// WithSpoofIPAddress spoofs the IP address of the machine which is running nmap.
// This can be used if nmap is unable to determine your source address.
// Another possible use of this flag is to spoof the scan to make the targets
// think that someone else is scanning them. The WithInterface option and
// WithSkipHostDiscovery are generally required for this sort of usage. Note
// that you usually won't receive reply packets back (they will be addressed to
// the IP you are spoofing), so Nmap won't produce useful reports.
func WithSpoofIPAddress(ip string) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-S")
		s.args = append(s.args, ip)
	}
}

// WithInterface specifies which network interface to use for scanning.
func WithInterface(iface string) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-e")
		s.args = append(s.args, iface)
	}
}

// WithSourcePort specifies from which port to scan.
func WithSourcePort(port int16) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--source-port")
		s.args = append(s.args, fmt.Sprint(port))
	}
}

// WithProxies allows to relay connection through HTTP/SOCKS4 proxies.
func WithProxies(proxies ...string) func(*Scanner) {
	proxyList := strings.Join(proxies, ",")

	return func(s *Scanner) {
		s.args = append(s.args, "--proxies")
		s.args = append(s.args, proxyList)
	}
}

// WithHexData appends a custom hex-encoded payload to sent packets.
func WithHexData(data string) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--data")
		s.args = append(s.args, data)
	}
}

// WithASCIIData appends a custom ascii-encoded payload to sent packets.
func WithASCIIData(data string) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--data-string")
		s.args = append(s.args, data)
	}
}

// WithDataLength appends a random payload of the given length to sent packets.
func WithDataLength(length int) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--data-length")
		s.args = append(s.args, fmt.Sprint(length))
	}
}

// WithIPOptions uses the specified IP options to send packets.
// You may be able to use the record route option to determine a
// path to a target even when more traditional traceroute-style
// approaches fail. See http://seclists.org/nmap-dev/2006/q3/52
// for examples of use.
func WithIPOptions(options string) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--ip-options")
		s.args = append(s.args, options)
	}
}

// WithIPTimeToLive sets the IP time-to-live field of IP packets.
func WithIPTimeToLive(ttl int16) func(*Scanner) {
	return func(s *Scanner) {
		if ttl < 0 || ttl > 255 {
			panic("value given to nmap.WithIPTimeToLive() should be between 0 and 255")
		}

		s.args = append(s.args, "--ttl")
		s.args = append(s.args, fmt.Sprint(ttl))
	}
}

// WithSpoofMAC uses the given MAC address for all of the raw
// ethernet frames the scanner sends. This option implies
// WithSendEthernet to ensure that Nmap actually sends ethernet-level
// packets.
// Valid argument examples are Apple, 0, 01:02:03:04:05:06,
// deadbeefcafe, 0020F2, and Cisco.
func WithSpoofMAC(argument string) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--spoof-mac")
		s.args = append(s.args, argument)
	}
}

// WithBadSum makes nmap send an invalid TCP, UDP or SCTP checksum
// for packets sent to target hosts. Since virtually all host IP
// stacks properly drop these packets, any responses received are
// likely coming from a firewall or IDS that didn't bother to
// verify the checksum.
func WithBadSum() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--badsum")
	}
}

/*** Output ***/

// WithVerbosity sets and increases the verbosity level of nmap.
func WithVerbosity(level int) func(*Scanner) {

	return func(s *Scanner) {
		if level < 0 || level > 10 {
			panic("value given to nmap.WithVerbosity() should be between 0 and 10")
		}
		s.args = append(s.args, fmt.Sprintf("-v%d", level))
	}
}

// WithDebugging sets and increases the debugging level of nmap.
func WithDebugging(level int) func(*Scanner) {
	return func(s *Scanner) {
		if level < 0 || level > 10 {
			panic("value given to nmap.WithDebugging() should be between 0 and 10")
		}
		s.args = append(s.args, fmt.Sprintf("-d%d", level))
	}
}

// WithReason makes nmap specify why a port is in a particular state.
func WithReason() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--reason")
	}
}

// WithOpenOnly makes nmap only show open ports.
func WithOpenOnly() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--open")
	}
}

// WithPacketTrace makes nmap show all packets sent and received.
func WithPacketTrace() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--packet-trace")
	}
}

// WithInterfaceList makes nmap print host interfaces and routes.
func WithInterfaceList() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--iflist")
	}
}

// WithAppendOutput makes nmap append to files instead of overwriting them.
// Currently does nothing, since this library doesn't write in files.
func WithAppendOutput() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--append-output")
	}
}

// WithResumePreviousScan makes nmap continue a scan that was aborted,
// from an output file.
func WithResumePreviousScan(filePath string) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--resume")
		s.args = append(s.args, filePath)
	}
}

// WithStylesheet makes nmap apply an XSL stylesheet to transform its
// XML output to HTML.
func WithStylesheet(stylesheetPath string) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--stylesheet")
		s.args = append(s.args, stylesheetPath)
	}
}

// WithWebXML makes nmap apply the default nmap.org stylesheet to transform
// XML output to HTML. The stylesheet can be found at
// https://nmap.org/svn/docs/nmap.xsl
func WithWebXML() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--webxml")
	}
}

// WithNoStylesheet prevents the use of XSL stylesheets with the XML output.
func WithNoStylesheet() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--no-stylesheet")
	}
}

/*** Misc ***/

// WithIPv6Scanning enables the use of IPv6 scanning.
func WithIPv6Scanning() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-6")
	}
}

// WithAggressiveScan enables the use of aggressive scan options. This has
// the same effect as using WithOSDetection, WithServiceInfo, WithDefaultScript
// and WithTraceRoute at the same time.
// Because script scanning with the default set is considered intrusive, you
// should not use this method against target networks without permission.
func WithAggressiveScan() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "-A")
	}
}

// WithDataDir specifies a custom data directory for nmap to get its
// nmap-service-probes, nmap-services, nmap-protocols, nmap-rpc,
// nmap-mac-prefixes, and nmap-os-db.
func WithDataDir(directoryPath string) func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--datadir")
		s.args = append(s.args, directoryPath)
	}
}

// WithSendEthernet makes nmap send packets at the raw ethernet (data link)
// layer rather than the higher IP (network) layer. By default, nmap chooses
// the one which is generally best for the platform it is running on.
func WithSendEthernet() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--send-eth")
	}
}

// WithSendIP makes nmap send packets via raw IP sockets rather than sending
// lower level ethernet frames.
func WithSendIP() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--send-ip")
	}
}

// WithPrivileged makes nmap assume that the user is fully privileged.
func WithPrivileged() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--privileged")
	}
}

// WithUnprivileged makes nmap assume that the user lacks raw socket privileges.
func WithUnprivileged() func(*Scanner) {
	return func(s *Scanner) {
		s.args = append(s.args, "--unprivileged")
	}
}
