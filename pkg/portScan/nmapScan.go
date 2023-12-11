package portScan

import (
	"context"
	"github.com/GhostTroops/scan4all/lib/goSqlite_gorm/lib/scan/Const"
	"github.com/GhostTroops/scan4all/lib/goSqlite_gorm/pkg/models"
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/Ullaakut/nmap"
	"io"
	"log"
	"time"
)

func init() {
	util.RegInitFunc(func() {
		// 基于工厂方法构建
		util.EngineFuncFactory(Const.ScanType_Nmap, func(evt *models.EventData, args ...interface{}) {
			var Targets []string = args[0].([]string)
			var Ports []string = args[1].([]string)
			x1 := &Scanner{Targets: Targets, Ports: Ports}
			var streams []*Stream
			_, err := x1.Scan(func(s *Stream) {
				streams = append(streams, s)
			})
			if nil != err {
				log.Println("nmap scan is error ", err)
			}
			util.SendEngineLog(evt, Const.ScanType_Nmap, streams)
		})
	})
}

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
	Service            *nmap.Service
}
type Scanner struct {
	Targets []string
	Ports   []string
}

// Scan scans the target networks and tries to find RTSP streams within them.
//
// Targets can be:
//
//   - a subnet (e.g.: 172.16.100.0/24)
//   - an IP (e.g.: 172.16.100.10)
//   - a hostname (e.g.: localhost)
//   - a range of IPs (e.g.: 172.16.100.10-20)
//
// Ports can be:
//
//   - one or multiple Ports and port ranges separated by commas (e.g.: 554,8554-8560,18554-28554)
func (s *Scanner) Scan(fnCbk func(*Stream)) ([]*Stream, error) {
	log.Println("Scanning the network")
	ctx, cancel := context.WithTimeout(context.Background(), 1800*time.Minute)
	defer cancel()
	// -script-timeout 3m --unique
	// Run nmap command to discover open Ports on the specified Targets & Ports.
	// -F --top-Ports=65535 -n --unique --resolve-all -Pn -sU -sS --min-hostgroup 64 --max-retries 0 --host-timeout 10m --script-timeout 3m --version-intensity 9 --min-rate ${XRate} -T4  -iL $1 -oX $2
	var nmapScanner *nmap.Scanner
	var err error
	nmapScanner, err = nmap.NewScanner(
		nmap.WithBinaryPath(util.GetVal("nmapScan")),
		nmap.WithServiceInfo(),           // -sV, 非常慢，但是指纹信息非常全
		nmap.WithMinRate(5000),           //--min-rate ${XRate}
		nmap.WithVersionIntensity(9),     // --version-intensity 9
		nmap.WithDisabledDNSResolution(), // -n
		//nmap.WithSkipHostDiscovery(),     // -Pn
		//nmap.WithUDPScan(),                      // -sU,需要root
		//nmap.WithSYNScan(),                      // -sS,需要root
		nmap.WithMinHostgroup(64),               // --min-hostgroup 64
		nmap.WithMaxRetries(0),                  // --max-retries 0
		nmap.WithHostTimeout(10),                // --host-timeout 10m
		nmap.WithPorts(s.Ports...),              // 0-65535
		nmap.WithTimingTemplate(nmap.Timing(4)), // -T4
		nmap.WithTargets(s.Targets...),
		nmap.WithContext(ctx),
	)
	if err != nil {
		return nil, err
	}

	return s.scan(nmapScanner, fnCbk)
}

func (s *Scanner) scan(nmapScanner *nmap.Scanner, fnCbk func(*Stream)) ([]*Stream, error) {
	err := nmapScanner.RunAsync()
	if err != nil {
		return nil, err
	}

	// Get streams from nmap results.
	var streams []*Stream
	x3 := nmapScanner.GetStderr()
	go io.Copy(io.Discard, util.ScannerToReader(&x3))
	scanner1 := nmapScanner.GetStdout()
	for scanner1.Scan() {
		s091 := scanner1.Text()
		//log.Println(s091)
		if r09, err := nmap.Parse([]byte(s091)); nil == err {
			for _, host := range r09.Hosts {
				if len(host.Ports) == 0 || len(host.Addresses) == 0 {
					continue
				}
				for _, port := range host.Ports {
					if port.Status() != "open" {
						continue
					}
					for _, address := range host.Addresses {
						sts := &Stream{
							Device:  port.Service.Product,
							Address: address.Addr,
							Port:    port.ID,
							Service: &port.Service,
						}
						if nil != fnCbk {
							fnCbk(sts)
						}
						streams = append(streams, sts)
					}
				}
			}
		} else {
			//log.Println(err)
		}
	}
	log.Printf("Found %d  Real Time Streaming Protocol (RTSP)\n", len(streams))

	return streams, nil
}
