package runner

import (
	"net"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/veo/vscan/pkg/naabu/scan"
)

const banner = `
                  __
  ___  ___  ___ _/ /  __ __
 / _ \/ _ \/ _ \/ _ \/ // /
/_//_/\_,_/\_,_/_.__/\_,_/ v2.0.5
`

// Version is the current version of naabu
const Version = `2.0.5`

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
	gologger.Info().Msgf("Port scan starting, running %s scan with %s privileges\n", scanType, accessLevel)
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
