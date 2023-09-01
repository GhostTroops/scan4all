package asnmap

import (
	"github.com/projectdiscovery/retryabledns"
)

var resolvers = []string{"8.8.8.8:53", "8.8.4.4:53"}
var max_retries = 2

func ResolveDomain(domain string, customresolvers ...string) ([]string, error) {
	// it requires a list of resolvers
	if len(customresolvers) == 0 {
		customresolvers = resolvers
	}
	dnsClient, _ := retryabledns.New(customresolvers, max_retries)
	var list []string

	ips, err := dnsClient.A(domain)
	if err != nil {
		return nil, err
	}
	list = append(list, ips.A...)

	ipA4, err := dnsClient.AAAA(domain)
	if err != nil {
		return nil, err
	}
	list = append(list, ipA4.AAAA...)
	return list, nil
}
