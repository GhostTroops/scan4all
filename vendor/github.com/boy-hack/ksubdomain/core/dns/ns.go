package dns

import (
	"errors"
	"github.com/miekg/dns"
	"net"
)

// LookupNS returns the names servers for a domain.
func LookupNS(domain, serverAddr string) (servers []string, ips []string, err error) {
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	in, err := dns.Exchange(m, serverAddr+":53")
	if err != nil {
		return nil, nil, err
	}
	if len(in.Answer) == 0 {
		return nil, nil, errors.New("no Answer")
	}
	for _, a := range in.Answer {
		if ns, ok := a.(*dns.NS); ok {
			servers = append(servers, ns.Ns)
		}
	}
	for _, s := range servers {
		ipResults, err := net.LookupIP(s)
		if err != nil {
			continue
		}
		for _, ip := range ipResults {
			if ip.To4() != nil {
				ips = append(ips, ip.To4().String())
			}
		}
	}
	return
}
