package ms

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"regexp"
	"strings"
)

var Match_IPv6 = regexp.MustCompile(`^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?$`)

var Match_IPv4 = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))$`)

var IPv4_Masks = map[uint32]uint32{
	1:          32,
	2:          31,
	4:          30,
	8:          29,
	16:         28,
	32:         27,
	64:         26,
	128:        25,
	256:        24,
	512:        23,
	1024:       22,
	2048:       21,
	4096:       20,
	8192:       19,
	16384:      18,
	32768:      17,
	65536:      16,
	131072:     15,
	262144:     14,
	524288:     13,
	1048576:    12,
	2097152:    11,
	4194304:    10,
	8388608:    9,
	16777216:   8,
	33554432:   7,
	67108864:   6,
	134217728:  5,
	268435456:  4,
	536870912:  3,
	1073741824: 2,
	2147483648: 1,
}

var IPv4_Mask_Sizes = []uint32{
	2147483648,
	1073741824,
	536870912,
	268435456,
	134217728,
	67108864,
	33554432,
	16777216,
	8388608,
	4194304,
	2097152,
	1048576,
	524288,
	262144,
	131072,
	65536,
	32768,
	16384,
	8192,
	4096,
	2048,
	1024,
	512,
	256,
	128,
	64,
	32,
	16,
	8,
	4,
	2,
	1,
}

func IPv4_to_UInt(ips string) (uint32, error) {
	ip := net.ParseIP(ips)
	if ip == nil {
		return 0, errors.New("Invalid IPv4 address")
	}
	ip = ip.To4()
	return binary.BigEndian.Uint32(ip), nil
}

func UInt_to_IPv4(ipi uint32) string {
	ipb := make([]byte, 4)
	binary.BigEndian.PutUint32(ipb, ipi)
	ip := net.IP(ipb)
	return ip.String()
}

func IPv4Range2CIDRs(s_ip string, e_ip string) ([]string, error) {

	s_i, s_e := IPv4_to_UInt(s_ip)
	if s_e != nil {
		return []string{}, s_e
	}

	e_i, e_e := IPv4_to_UInt(e_ip)
	if e_e != nil {
		return []string{}, e_e
	}

	if s_i > e_i {
		return []string{}, errors.New("Start address is bigger than end address")
	}

	return IPv4UIntRange2CIDRs(s_i, e_i), nil
}

func IPv4UIntRange2CIDRs(s_i uint32, e_i uint32) []string {
	cidrs := []string{}

	// Ranges are inclusive
	size := e_i - s_i + 1

	if size == 0 {
		return cidrs
	}

	for i := range IPv4_Mask_Sizes {

		mask_size := IPv4_Mask_Sizes[i]

		if mask_size > size {
			continue
		}

		// Exact match of the block size
		if mask_size == size {
			cidrs = append(cidrs, fmt.Sprintf("%s/%d", UInt_to_IPv4(s_i), IPv4_Masks[mask_size]))
			break
		}

		// Chop off the biggest block that fits
		cidrs = append(cidrs, fmt.Sprintf("%s/%d", UInt_to_IPv4(s_i), IPv4_Masks[mask_size]))
		s_i = s_i + mask_size

		// Look for additional blocks
		new_cidrs := IPv4UIntRange2CIDRs(s_i, e_i)

		// Merge those blocks into out results
		for x := range new_cidrs {
			cidrs = append(cidrs, new_cidrs[x])
		}
		break

	}
	return cidrs
}

func AddressesFromCIDR(cidr string, o chan<- string) {
	if len(cidr) == 0 {
		return
	}

	// We may receive bare IP addresses, not CIDRs sometimes
	if !strings.Contains(cidr, "/") {
		if strings.Contains(cidr, ":") {
			cidr = cidr + "/128"
		} else {
			cidr = cidr + "/32"
		}
	}

	// Parse CIDR into base address + mask
	ip, net, err := net.ParseCIDR(cidr)
	if err != nil {
		//fmt.Fprintf(os.Stderr, "Invalid CIDR %s: %s\n", cidr, err.Error())
		return
	}

	// Verify IPv4 for now
	ip4 := net.IP.To4()
	if ip4 == nil {
		fmt.Fprintf(os.Stderr, "Invalid IPv4 CIDR %s\n", cidr)
		return
	}

	net_base, err := IPv4_to_UInt(net.IP.String())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid IPv4 Address %s: %s\n", ip.String(), err.Error())
		return
	}

	mask_ones, mask_total := net.Mask.Size()

	// Does not work for IPv6 due to cast to uint32
	net_size := uint32(math.Pow(2, float64(mask_total-mask_ones)))

	cur_base := net_base
	end_base := net_base + net_size
	cur_addr := cur_base

	for cur_addr = cur_base; cur_addr < end_base; cur_addr++ {
		o <- UInt_to_IPv4(cur_addr)
	}

	return
}
