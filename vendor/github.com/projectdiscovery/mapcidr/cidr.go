// Package mapcidr implements methods to allow working with CIDRs.
package mapcidr

import (
	"fmt"
	"math"
	"math/big"
	"net"
)

// AddressRange returns the first and last addresses in the given CIDR range.
func AddressRange(network *net.IPNet) (firstIP, lastIP net.IP, err error) {
	firstIP = network.IP

	prefixLen, bits := network.Mask.Size()
	if prefixLen == bits {
		lastIP := make([]byte, len(firstIP))
		copy(lastIP, firstIP)
		return firstIP, lastIP, nil
	}

	firstIPInt, bits, err := IPToInteger(firstIP)
	if err != nil {
		return nil, nil, err
	}
	hostLen := uint(bits) - uint(prefixLen)
	lastIPInt := big.NewInt(1)
	lastIPInt.Lsh(lastIPInt, hostLen)
	lastIPInt.Sub(lastIPInt, big.NewInt(1))
	lastIPInt.Or(lastIPInt, firstIPInt)
	lastIP = IntegerToIP(lastIPInt, bits)
	return
}

// AddressCount returns the number of IP addresses in a range
func AddressCount(cidr string) (uint64, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, err
	}
	return AddressCountIpnet(ipnet), nil
}

// AddressCountIpnet returns the number of IP addresses in an IPNet structure
//
// NOTE(dwisiswant0): This function uses uint64 and will overflow for IPv6 CIDRs
// larger than /64 (e.g., /63, /48). Functions like SplitIPNetIntoN were
// modified to work based on available prefix bits rather than the total address
// count to avoid this overflow issue w/o requiring big.Int calcs for splitting.
// But, direct usage of this function or functions relying on it
// (like SplitIPNetByNumber) will still produce incorrect results for large IPv6
// ranges.
func AddressCountIpnet(network *net.IPNet) uint64 {
	prefixLen, bits := network.Mask.Size()
	return 1 << (uint64(bits) - uint64(prefixLen))
}

// SplitByNumber splits the given cidr into subnets with the closest
// number of hosts per subnet.
func SplitByNumber(iprange string, number int) ([]*net.IPNet, error) {
	_, ipnet, err := net.ParseCIDR(iprange)
	if err != nil {
		return nil, err
	}
	return SplitIPNetByNumber(ipnet, number)
}

// SplitIPNetByNumber splits an IPNet into subnets with the closest n
// umber of hosts per subnet.
func SplitIPNetByNumber(ipnet *net.IPNet, number int) ([]*net.IPNet, error) {
	ipsNumber := AddressCountIpnet(ipnet)

	// truncate result to nearest uint64
	optimalSplit := int(ipsNumber / uint64(number))
	return SplitIPNetIntoN(ipnet, optimalSplit)
}

// SplitN attempts to split a cidr in the exact number of subnets
func SplitN(iprange string, n int) ([]*net.IPNet, error) {
	_, ipnet, err := net.ParseCIDR(iprange)
	if err != nil {
		return nil, err
	}
	return SplitIPNetIntoN(ipnet, n)
}

// SplitIPNetIntoN attempts to split a ipnet in the exact number of subnets
func SplitIPNetIntoN(iprange *net.IPNet, n int) ([]*net.IPNet, error) {
	var err error
	subnets := make([]*net.IPNet, 0, n)

	prefixLen, bits := iprange.Mask.Size()
	availableBits := bits - prefixLen
	requiredBits := 0
	if n > 1 {
		requiredBits = int(math.Ceil(math.Log2(float64(n))))
	}

	// invalid value or impossible split
	if n <= 1 || availableBits < requiredBits {
		subnets = append(subnets, iprange)
		return subnets, nil
	}
	// power of two
	if isPowerOfTwo(n) { // isPowerOfTwoPlusOne(n)
		return splitIPNet(iprange, n)
	}

	var closestMinorPowerOfTwo int
	// find the closest power of two less than or equal to n
	for i := n; i > 0; i-- {
		if isPowerOfTwo(i) {
			closestMinorPowerOfTwo = i
			break
		}
	}

	subnets, err = splitIPNet(iprange, closestMinorPowerOfTwo)
	if err != nil {
		return nil, err
	}
	for len(subnets) < n {
		lastSubnet := subnets[len(subnets)-1]

		// NOTE(dwisiswant0): divide the last subnet into two
		divided, err := divideIPNet(lastSubnet)
		if err != nil {
			// NOTE(dwisiswant0): This can happen if we try to split a /32 or /128
			return nil, fmt.Errorf("cannot divide subnet %s further to reach %d splits: %w", lastSubnet, n, err)
		}

		subnets = subnets[:len(subnets)-1]
		subnets = append(subnets, divided...)
	}

	return subnets, nil
}

// divideIPNet divides an IPNet into two IPNet structures.
func divideIPNet(ipnet *net.IPNet) ([]*net.IPNet, error) {
	subnets := make([]*net.IPNet, 0, 2) //nolint

	maskBits, _ := ipnet.Mask.Size()
	wantedMaskBits := maskBits + 1

	currentSubnet, err := currentSubnet(ipnet, wantedMaskBits)
	if err != nil {
		return nil, err
	}
	subnets = append(subnets, currentSubnet)
	nextSubnet, err := nextSubnet(currentSubnet, wantedMaskBits)
	if err != nil {
		return nil, err
	}
	subnets = append(subnets, nextSubnet)

	return subnets, nil
}

// splitIPNet into approximate N counts
func splitIPNet(ipnet *net.IPNet, n int) ([]*net.IPNet, error) {
	var err error
	subnets := make([]*net.IPNet, 0, n)

	maskBits, _ := ipnet.Mask.Size()
	closestPow2 := int(closestPowerOfTwo(uint32(n)))
	pow2 := int(math.Log2(float64(closestPow2)))

	wantedMaskBits := maskBits + pow2

	currentSubnet, err := currentSubnet(ipnet, wantedMaskBits)
	if err != nil {
		return nil, err
	}
	subnets = append(subnets, currentSubnet)
	nxtSubnet := currentSubnet
	for i := 0; i < closestPow2-1; i++ {
		nxtSubnet, err = nextSubnet(nxtSubnet, wantedMaskBits)
		if err != nil {
			return nil, err
		}
		subnets = append(subnets, nxtSubnet)
	}

	if len(subnets) < n {
		lastSubnet := subnets[len(subnets)-1]
		subnets = subnets[:len(subnets)-1]
		ipnets, err := divideIPNet(lastSubnet)
		if err != nil {
			return nil, err
		}
		subnets = append(subnets, ipnets...)
	}
	return subnets, nil
}

// func split(iprange string, n int) ([]*net.IPNet, error) {
// 	_, ipnet, _ := net.ParseCIDR(iprange)
// 	return splitIPNet(ipnet, n)
// }

func nextPowerOfTwo(v uint32) uint32 {
	v--
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	v++
	return v
}

func closestPowerOfTwo(v uint32) uint32 {
	next := nextPowerOfTwo(v)
	if prev := next / 2; (v - prev) < (next - v) {
		next = prev
	}
	return next
}

func currentSubnet(network *net.IPNet, prefixLen int) (*net.IPNet, error) {
	currentFirst, _, err := AddressRange(network)
	if err != nil {
		return nil, err
	}
	mask := net.CIDRMask(prefixLen, 8*len(currentFirst)) //nolint
	return &net.IPNet{IP: currentFirst.Mask(mask), Mask: mask}, nil
}

// nextSubnet returns the next subnet for an ipnet
func nextSubnet(network *net.IPNet, prefixLen int) (*net.IPNet, error) {
	_, currentLast, err := AddressRange(network)
	if err != nil {
		return nil, err
	}
	mask := net.CIDRMask(prefixLen, 8*len(currentLast)) //nolint
	currentSubnet := &net.IPNet{IP: currentLast.Mask(mask), Mask: mask}
	_, last, err := AddressRange(currentSubnet)
	if err != nil {
		return nil, err
	}
	last = inc(last)
	next := &net.IPNet{IP: last.Mask(mask), Mask: mask}
	if last.Equal(net.IPv4zero) || last.Equal(net.IPv6zero) {
		return next, nil
	}
	return next, nil
}

// isPowerOfTwoPlusOne returns if a number is a power of 2 plus 1
//
// NOTE(dwisiswant0): This function is no longer used. The logic in
// SplitIPNetIntoN was refactored to correctly handle non-power-of-two splits by
// first splitting into the largest power-of-two less than or equal to n, and
// then iteratively dividing the last subnet. This removed the need for this
// specific check.
//
// nolint:all
// func isPowerOfTwoPlusOne(x int) bool {
// 	return isPowerOfTwo(x - 1)
// }

// isPowerOfTwo returns if a number is a power of 2
func isPowerOfTwo(x int) bool {
	return x != 0 && (x&(x-1)) == 0
}

// reverseIPNet reverses an ipnet slice
//
// nolint:all
// func reverseIPNet(ipnets []*net.IPNet) {
// 	for i, j := 0, len(ipnets)-1; i < j; i, j = i+1, j-1 {
// 		ipnets[i], ipnets[j] = ipnets[j], ipnets[i]
// 	}
// }

// IPAddresses returns all the IP addresses in a CIDR
func IPAddresses(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return []string{}, err
	}
	return IPAddressesIPnet(ipnet), nil
}

func IPAddressesAsStream(cidr string) (chan string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return IpAddresses(ipnet), nil
}

// IPAddressesIPnet returns all IP addresses in an IPNet.
func IPAddressesIPnet(ipnet *net.IPNet) (ips []string) {
	for ip := range IpAddresses(ipnet) {
		ips = append(ips, ip)
	}
	return ips
}

// IpAddresses as stream
func IpAddresses(ipnet *net.IPNet) (ips chan string) {
	ips = make(chan string)
	go func() {
		defer close(ips)

		netWithRange := ipNetToRange(*ipnet)
		for ip := *netWithRange.First; !ip.Equal(*netWithRange.Last); ip = GetNextIP(ip) {
			ips <- ip.String()
		}

		// Add the last IP
		ips <- netWithRange.Last.String()
	}()
	return ips
}

// IPToInteger converts an IP address to its integer representation.
// It supports both IPv4 as well as IPv6 addresses.
func IPToInteger(ip net.IP) (*big.Int, int, error) {
	val := new(big.Int)

	// check if the ip is v4 => convert to 4 bytes representation
	if ipv4 := ip.To4(); ipv4 != nil {
		val.SetBytes(ipv4)
		return val, 32, nil
	}

	// check if the ip is v6 => convert to 16 bytes representation
	if ipv6 := ip.To16(); ipv6 != nil {
		val.SetBytes(ipv6)
		return val, 128, nil
	}

	return nil, 0, fmt.Errorf("unsupported IP address format")
}

// IntegerToIP converts an Integer IP address to net.IP format.
func IntegerToIP(ipInt *big.Int, bits int) net.IP {
	ipBytes := ipInt.Bytes()
	ret := make([]byte, bits/8) //nolint
	for i := 1; i <= len(ipBytes); i++ {
		ret[len(ret)-i] = ipBytes[len(ipBytes)-i]
	}
	return net.IP(ret)
}
