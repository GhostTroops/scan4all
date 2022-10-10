package dnsx

import (
	"net"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/iputil"
)

// CdnCheck verifies if the given ip is part of Cdn ranges
func (d *DNSX) CdnCheck(domain string) (bool, string, error) {
	if d.cdn == nil {
		return false, "", errors.New("cdn client not initialized")
	}
	ips, err := net.LookupIP(domain)
	if err != nil {
		return false, "", err
	}
	ipAddr := ips[0].String()
	if !iputil.IsIP(ipAddr) {
		return false, "", errors.Errorf("%s is not a valid ip", ipAddr)
	}
	return d.cdn.Check(net.ParseIP((ipAddr)))
}
