package go_utils

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net"
	"strings"
)

// ipv4 to bigint
// ipv6 to bigint
func Ip2Int(ip net.IP) *big.Int {
	i := big.NewInt(0)
	i.SetBytes(ip)
	return i
}

// ipv4 string to bigint
// ipv6 string to bigint
func StrIp2Int(ip string) *big.Int {
	return Ip2Int(net.ParseIP(ip))
}

func IsIPv4(address string) bool {
	return strings.Count(address, ":") < 2
}

func IsIPv6(str string) bool {
	return strings.Count(str, ":") >= 2
}

// big int to Ip
func IntToIpv6(intipv6 *big.Int) *net.IP {
	ip := intipv6.Bytes()
	var a net.IP = ip
	if IsIPv4(a.String()) {
		a = ip[len(ip)-4:]
	}

	ip1 := a.To4()
	if nil != ip1 {
		return &ip1
	}
	return &a
}

// string big int to big int
// If the string input tosetString() starts with “0x” base 16 (hexadecimal) will be used.
//  If the string starts with “0” base 8 (octal) will be used.
// Otherwise it will use base 10 (decimal)
func Str2BigInt(s string, base int) *big.Int {
	bi := new(big.Int)
	bi.SetString(s, base)
	return bi
}

func FullIPv6(ip net.IP) string {
	dst := make([]byte, hex.EncodedLen(len(ip)))
	_ = hex.Encode(dst, ip)
	return string(dst[0:4]) + ":" +
		string(dst[4:8]) + ":" +
		string(dst[8:12]) + ":" +
		string(dst[12:16]) + ":" +
		string(dst[16:20]) + ":" +
		string(dst[20:24]) + ":" +
		string(dst[24:28]) + ":" +
		string(dst[28:])
}

// big int to ip(v6) string
func IntToIpv6Str(intipv6 *big.Int) string {
	ip := IntToIpv6(intipv6)
	s1 := ip.String()
	if IsIPv4(s1) {
		return s1
	} else {
		return FullIPv6(*ip)
	}
}

// big int to hex, base is 16
func BigInt2Hex(v *big.Int, base int) string {
	return v.Text(base)
}

// int to hex string
func Any2Hex(v interface{}) string {
	data, err := json.Marshal(v)
	if nil != err {
		log.Println("Any2Hex is error: ", err)
		return ""
	}
	return fmt.Sprintf("%x", data)
}
