package core

import "net"

func IsWildCard(domain string) bool {
	for i := 0; i < 2; i++ {
		subdomain := RandomStr(6) + "." + domain
		_, err := net.LookupIP(subdomain)
		if err != nil {
			continue
		}
		return true
	}
	return false
}
