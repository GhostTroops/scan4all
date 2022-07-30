package nmap

import (
	"log"
	"strings"

	"github.com/Ullaakut/nmap"
)

// Stream represents a camera's RTSP stream
type Stream struct {
	Device   string   `json:"device"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	Routes   []string `json:"route"`
	Address  string   `json:"address" validate:"required"`
	Port     uint16   `json:"port" validate:"required"`

	CredentialsFound bool `json:"credentials_found"`
	RouteFound       bool `json:"route_found"`
	Available        bool `json:"available"`

	AuthenticationType int `json:"authentication_type"`
}
type Scanner struct {
	targets []string
	ports   []string
}

// Scan scans the target networks and tries to find RTSP streams within them.
//
// targets can be:
//
//    - a subnet (e.g.: 172.16.100.0/24)
//    - an IP (e.g.: 172.16.100.10)
//    - a hostname (e.g.: localhost)
//    - a range of IPs (e.g.: 172.16.100.10-20)
//
// ports can be:
//
//    - one or multiple ports and port ranges separated by commas (e.g.: 554,8554-8560,18554-28554)
func (s *Scanner) Scan() ([]Stream, error) {
	log.Println("Scanning the network")

	// -script-timeout 3m --unique
	// Run nmap command to discover open ports on the specified targets & ports.
	// -F --top-ports=65535 -n --unique --resolve-all -Pn -sU -sS --min-hostgroup 64 --max-retries 0 --host-timeout 10m --script-timeout 3m --version-intensity 9 --min-rate ${XRate} -T4  -iL $1 -oX $2
	nmapScanner, err := nmap.NewScanner(
		nmap.WithTargets(s.targets...),
		nmap.WithMostCommonPorts(65535),
		nmap.WithMinRate(5000),           //--min-rate ${XRate}
		nmap.WithVersionIntensity(9),     // --version-intensity 9
		nmap.WithDisabledDNSResolution(), // -n
		nmap.WithSkipHostDiscovery(),     // -Pn
		nmap.WithUDPScan(),               // -sU
		nmap.WithSYNScan(),               // -sS
		nmap.WithMinHostgroup(64),        // --min-hostgroup 64
		nmap.WithMaxRetries(0),           // --max-retries 0
		nmap.WithHostTimeout(10),         // --host-timeout 10m
		//nmap.WithPorts(s.ports...),            // 1-65535
		nmap.WithVersionAll(),                   //--version-all
		nmap.WithTimingTemplate(nmap.Timing(4)), // -T4
	)
	if err != nil {
		return nil, err
	}

	return s.scan(nmapScanner)
}

func (s *Scanner) scan(nmapScanner nmap.ScanRunner) ([]Stream, error) {
	results, _, err := nmapScanner.Run()
	if err != nil {
		return nil, err
	}

	// Get streams from nmap results.
	var streams []Stream
	for _, host := range results.Hosts {
		for _, port := range host.Ports {
			if port.Status() != "open" {
				continue
			}

			if !strings.Contains(port.Service.Name, "rtsp") {
				continue
			}

			for _, address := range host.Addresses {
				streams = append(streams, Stream{
					Device:  port.Service.Product,
					Address: address.Addr,
					Port:    port.ID,
				})
			}
		}
	}

	log.Println("Found %d RTSP streams\n", len(streams))

	return streams, nil
}
