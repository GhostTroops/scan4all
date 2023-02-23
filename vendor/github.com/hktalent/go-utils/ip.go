package go_utils

import (
	"encoding/hex"
	"fmt"
	"github.com/pion/stun"
	"log"
	"math/big"
	"net"
	"strings"
)

// get your public ip
// auto skip proxy
func GetPublicIp() string {
	c, err := stun.Dial("udp", "stun.l.google.com:19302")
	if err != nil {
		log.Println(err)
		return ""
	}
	szR := ""
	// Building binding request with random transaction id.
	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	// Sending request to STUN server, waiting for response message.
	if err := c.Do(message, func(res stun.Event) {
		if res.Error != nil {
			log.Println(err)
			return
		}
		// Decoding XOR-MAPPED-ADDRESS attribute from message.
		var xorAddr stun.XORMappedAddress
		if err := xorAddr.GetFrom(res.Message); err != nil {
			log.Println(err)
		}
		szR = xorAddr.IP.String()
		fmt.Println("your IP is", szR)
	}); err != nil {
		log.Println(err)
	}
	return szR
}

// Get the Internet egress ip of the current machine
func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

// 获取domain的所有ip
func GetIps(domain string) []string {
	UseCacheIp := GetValAsBool("UseCacheIp")
	if UseCacheIp {
		a, err := GetAny[[]string](domain)
		if nil == err {
			return a
		}
	}
	a1 := GetDomian2IpsAll(domain)
	if nil != a1 && 0 < len(a1) {
		go PutAny[[]string](domain, a1)
	}
	return a1
}

// domain
// opType 0 all type，1 ipv4，2 ipv6
func GetDomian2Ips(domain string, opType int) []string {
	ips, _ := net.LookupIP(domain)
	var aIps []string
	for _, ip := range ips {
		if 0 == opType || 1 == opType {
			if ipv4 := ip.To4(); ipv4 != nil {
				aIps = append(aIps, ipv4.String())
			}
		}
		if 0 == opType || 2 == opType {
			if ipv6 := ip.To16(); ipv6 != nil {
				aIps = append(aIps, ipv6.String())
			}
		}
	}
	return aIps
}

func GetDomian2IpsAll(domain string) []string {
	return GetDomian2Ips(domain, 0)
}

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
//
//	If the string starts with “0” base 8 (octal) will be used.
//
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
	data, err := Json.Marshal(v)
	if nil != err {
		log.Println("Any2Hex is error: ", err)
		return ""
	}
	return fmt.Sprintf("%x", data)
}
