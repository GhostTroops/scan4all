package runner

import (
	"io/ioutil"
	"net"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/veo/vscan/pkg/naabu/scan"
)

const banner = `
                  __
  ___  ___  ___ _/ /  __ __
 / _ \/ _ \/ _ \/ _ \/ // /
/_//_/\_,_/\_,_/_.__/\_,_/ v2.0.4
`

// Version is the current version of naabu
const Version = `1.0.6`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")

	gologger.Print().Msgf("Use with caution. You are responsible for your actions\n")
	gologger.Print().Msgf("Developers assume no liability and are not responsible for any misuse or damage.\n")
}

// showNetworkCapabilities shows the network capabilities/scan types possible with the running user
func showNetworkCapabilities(options *Options) {
	accessLevel := "non root"
	scanType := "CONNECT"
	if isRoot() && options.ScanType == SynScan {
		accessLevel = "root"
		scanType = "SYN"
	}
	gologger.Info().Msgf("Running %s scan with %s privileges\n", scanType, accessLevel)
}

func showNetworkInterfaces() error {
	// Interfaces List
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, itf := range interfaces {
		addresses, addErr := itf.Addrs()
		if addErr != nil {
			gologger.Warning().Msgf("Could not retrieve addresses for %s: %s\n", itf.Name, addErr)
			continue
		}
		var addrstr []string
		for _, address := range addresses {
			addrstr = append(addrstr, address.String())
		}
		gologger.Info().Msgf("Interface %s:\nMAC: %s\nAddresses: %s\nMTU: %d\nFlags: %s\n", itf.Name, itf.HardwareAddr, strings.Join(addrstr, " "), itf.MTU, itf.Flags.String())
	}
	// External ip
	externalIP, err := scan.WhatsMyIP()
	if err != nil {
		gologger.Warning().Msgf("Could not obtain public ip: %s\n", err)
	}
	gologger.Info().Msgf("External Ip: %s\n", externalIP)

	return nil
}

func (options *Options) writeDefaultConfig() {
	dummyconfig := `
# Number of retries
# retries: 1
# Packets rate
# rate: 100
# Timeout is the seconds to wait for ports to respond
# timeout: 5
# Hosts are the host to find ports for
# host:
# 	- 10.10.10.10
# Ports is the ports to use for enumeration
# ports:
# 	- 80
# 	- 100
# ExcludePorts is the list of ports to exclude from enumeration
# exclude-ports:
# 	- 20
# 	- 30
# Verify is used to check if the ports found were valid using CONNECT method
# verify: false
# NoProbe skips probes to discover alive hosts
# Ips or cidr to be excluded from the scan
# exclude-ips:
# 	- 1.1.1.1
# 	- 2.2.2.2
# Top ports list
# top-ports: 100
# Attempts to run as root
# privileged: true
# Drop root privileges
# unprivileged: true
# Excludes ip of knows CDN ranges
# exclude-cdn: true
# SourceIP to use in TCP packets
# source-ip: 10.10.10.10
# Interface to use for TCP packets
# interface: eth0
# WarmUpTime between scan phases
# warm-up-time: 2
# nmap command to invoke after scanning
# nmap: nmap -sV
`
	configFile, err := getDefaultConfigFile()
	if err != nil {
		gologger.Warning().Msgf("Could not get default configuration file: %s\n", err)
	}
	if fileExists(configFile) {
		return
	}

	err = ioutil.WriteFile(configFile, []byte(dummyconfig), 0755)
	if err != nil {
		gologger.Warning().Msgf("Could not write configuration file to %s: %s\n", configFile, err)
		return
	}
	gologger.Info().Msgf("Configuration file saved to %s\n", configFile)
}
