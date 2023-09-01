package asnmap

import (
	"net"

	"github.com/projectdiscovery/mapcidr"
)

func GetCIDR(output []*Response) ([]*net.IPNet, error) {
	var cidrs []*net.IPNet
	for _, res := range output {
		cidr, err := mapcidr.GetCIDRFromIPRange(net.ParseIP(res.FirstIp), net.ParseIP(res.LastIp))
		if err != nil {
			return nil, err
		}
		cidrs = append(cidrs, cidr...)
	}
	return cidrs, nil
}
