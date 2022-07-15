package snmp

import (
	"github.com/gosnmp/gosnmp"
)

type IpAddr struct {
	Ip       string
	Port     int
	Protocol string
}
type Service struct {
	Ip       string
	Port     int
	Protocol string
	Username string
	Password string
}
type ScanResult struct {
	Service *Service
	Result  bool
}

// default port: 161/162,
// more see: https://nmap.org/book/scan-methods-udp-scan.html
func ScanSNMP(s *Service) (err error, result *ScanResult) {
	result.Service = s
	result.Service.Username = s.Username // default public
	result.Service.Password = s.Password // default public
	gosnmp.Default.Target = s.Ip
	gosnmp.Default.Port = uint16(s.Port)
	gosnmp.Default.Community = result.Service.Password
	gosnmp.Default.Timeout = 10

	err = gosnmp.Default.Connect()
	if err == nil {
		oids := []string{"1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.7.0"}
		_, err := gosnmp.Default.Get(oids)
		if err == nil {
			result.Result = true
		}
	}

	return err, result
}
