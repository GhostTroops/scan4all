package iputil

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/projectdiscovery/mapcidr"
)

// IsIP checks if a string is either IP version 4 or 6. Alias for `net.ParseIP`
func IsIP(str string) bool {
	return net.ParseIP(str) != nil
}

// IsPort checks if a string represents a valid port
func IsPort(str string) bool {
	if i, err := strconv.Atoi(str); err == nil && i > 0 && i < 65536 {
		return true
	}
	return false
}

// IsIPv4 checks if the string is an IP version 4.
func IsIPv4(str string) bool {
	ip := net.ParseIP(str)
	return ip != nil && strings.Contains(str, ".")
}

// IsIPv6 checks if the string is an IP version 6.
func IsIPv6(str string) bool {
	ip := net.ParseIP(str)
	return ip != nil && strings.Contains(str, ":")
}

// IsCIDR checks if the string is an valid CIDR notiation (IPV4 & IPV6)
func IsCIDR(str string) bool {
	_, _, err := net.ParseCIDR(str)
	return err == nil
}

// IsCIDR checks if the string is an valid CIDR after replacing - with /
func IsCidrWithExpansion(str string) bool {
	str = strings.ReplaceAll(str, "-", "/")
	return IsCIDR(str)
}

// CountIPsInCIDR counts the number of ips in cidr
func CountIPsInCIDR(cidr string) int64 {
	_, c, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0
	}

	return mapcidr.CountIPsInCIDR(c).Int64()
}

// ToCidr converts a cidr string to net.IPNet pointer
func ToCidr(item string) *net.IPNet {
	if IsIP(item) {
		item += "/32"
	}
	if IsCIDR(item) {
		_, ipnet, _ := net.ParseCIDR(item)
		return ipnet
	}
	return nil
}

// AsIPV4CIDR converts ipv4 cidr to net.IPNet pointer
func AsIPV4IpNet(IPV4 string) *net.IPNet {
	if IsIPv4(IPV4) {
		IPV4 += "/32"
	}
	_, network, err := net.ParseCIDR(IPV4)
	if err != nil {
		return nil
	}
	return network
}

// AsIPV6IpNet converts ipv6 cidr to net.IPNet pointer
func AsIPV6IpNet(IPV6 string) *net.IPNet {
	if IsIPv6(IPV6) {
		IPV6 += "/64"
	}
	_, network, err := net.ParseCIDR(IPV6)
	if err != nil {
		return nil
	}
	return network
}

// AsIPV4CIDR converts ipv4 ip to cidr string
func AsIPV4CIDR(IPV4 string) string {
	if IsIP(IPV4) {
		return IPV4 + "/32"
	}
	return IPV4
}

// AsIPV4CIDR converts ipv6 ip to cidr string
func AsIPV6CIDR(IPV6 string) string {
	// todo
	return IPV6
}

// WhatsMyIP attempts to obtain the external ip through public api
// Copied from https://github.com/projectdiscovery/naabu/blob/master/v2/pkg/scan/externalip.go
func WhatsMyIP() (string, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.ipify.org?format=text", nil)
	if err != nil {
		return "", nil
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error fetching ip: %s", resp.Status)
	}

	ip, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(ip), nil
}
