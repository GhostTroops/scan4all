package runner

import (
	"net"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
)

const banner = `
                  __
  ___  ___  ___ _/ /  __ __
 / _ \/ _ \/ _ \/ _ \/ // /
/_//_/\_,_/\_,_/_.__/\_,_/ v2.1.0
`

// Version is the current version of naabu
const Version = `2.1.0`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")

	gologger.Print().Msgf("Use with caution. You are responsible for your actions\n")
	gologger.Print().Msgf("Developers assume no liability and are not responsible for any misuse or damage.\n")
}

// showNetworkCapabilities shows the network capabilities/scan types possible with the running user
func showNetworkCapabilities(options *Options) {
	var accessLevel, scanType string

	switch {
	case privileges.IsPrivileged && options.ScanType == SynScan:
		accessLevel = "root"
		if isLinux() {
			accessLevel = "CAP_NET_RAW"
		}
		scanType = "SYN"
	case options.Passive:
		accessLevel = "non root"
		scanType = "PASSIVE"
	default:
		accessLevel = "non root"
		scanType = "CONNECT"
	}

	switch {
	case options.HostDiscovery:
		scanType = "Host Discovery"
		gologger.Info().Msgf("Running %s\n", scanType)
	case options.Passive:
		scanType = "PASSIVE"
		gologger.Info().Msgf("Running %s scan\n", scanType)
	default:
		gologger.Info().Msgf("Running %s scan with %s privileges\n", scanType, accessLevel)
	}
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
