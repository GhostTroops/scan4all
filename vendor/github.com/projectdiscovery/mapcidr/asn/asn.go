package asn

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	asnmap "github.com/projectdiscovery/asnmap/libs"
	"github.com/projectdiscovery/mapcidr"
)

var DefaultClient *asnmap.Client

func init() {
	var err error
	DefaultClient, err = asnmap.NewClient()
	// DefaultClient must exist
	if err != nil {
		panic(err)
	}
}

// GetCIDRsForASNNum returns the slice of cidrs for given ASN number
// accept the ASN number like 'AS15133' and returns the CIDRs for that ASN
func GetCIDRsForASNNum(value string) ([]*net.IPNet, error) {
	var cidrs []*net.IPNet
	if len(value) < 3 {
		return nil, fmt.Errorf("invalid asn number %s", value)
	}
	data, err := DefaultClient.GetData(value[2:])
	if err != nil {
		return nil, err
	}
	cidrs, err = asnmap.GetCIDR(data)
	if err != nil {
		return nil, err
	}

	var filteredCIDRs []*net.IPNet
	for _, cidr := range cidrs {
		if mapcidr.IsIPv4(cidr.IP) {
			filteredCIDRs = append(filteredCIDRs, cidr)
		}
	}
	return filteredCIDRs, nil
}

// GetIPAddressesAsStream returns the chan of IP address for given ASN number
// returning the string chan for optimizing the memory
func GetIPAddressesAsStream(value string) (chan string, error) {
	cidrs, err := GetCIDRsForASNNum(value)
	if err != nil {
		return nil, err
	}
	ret := make(chan string)
	go func() {
		defer close(ret)
		for _, cidr := range cidrs {
			ips, _ := mapcidr.IPAddressesAsStream(cidr.String())
			for ip := range ips {
				ret <- ip
			}
		}
	}()
	return ret, nil
}

// IsASN checks if the given input is ASN or not,
// its possible to have an domain name starting with AS/as prefix.
func IsASN(value string) bool {
	if len(value) > 2 && strings.HasPrefix(strings.ToUpper(value), "AS") {
		_, err := strconv.Atoi(value[2:])
		return err == nil
	}
	return false
}
