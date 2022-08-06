package x

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
)

// IP2Decimal0 transform ip format like x.x.x.x to decimal.
// ref: https://zh.wikipedia.org/wiki/IPv4
func IP2Decimal0(ip string) (n int64, err error) {
	ss := strings.Split(ip, ".")
	var b string
	var s string
	var i int64
	if len(ss) != 4 {
		err = errors.New("IP Invalid")
		return
	}
	for _, s = range ss {
		i, err = strconv.ParseInt(s, 10, 64)
		if err != nil {
			return
		}
		s = strconv.FormatInt(i, 2)
		var j int
		need := 8 - len(s)
		for j = 0; j < need; j++ {
			s = "0" + s
		}
		b += s
	}
	n, _ = strconv.ParseInt(b, 2, 64)
	return
}

// IP2Decimal1 transform ip format like x.x.x.x to decimal.
func IP2Decimal1(ipstr string) (int64, error) {
	ip := net.ParseIP(ipstr)
	if ip == nil {
		return 0, errors.New("ParseIP error")
	}
	// ip is 16 bytes, but ipv4 is only in last 4 bytes
	d := uint32(ip[12])<<24 | uint32(ip[13])<<16 | uint32(ip[14])<<8 | uint32(ip[15])
	return int64(d), nil
}

// IP2Decimal transform ip format like x.x.x.x to decimal.
func IP2Decimal(ipstr string) (int64, error) {
	ip := net.ParseIP(ipstr)
	if ip == nil {
		return 0, errors.New("ParseIP error")
	}
	// ip is 16 bytes, but ipv4 is only in last 4 bytes
	d := binary.BigEndian.Uint32(ip[12:16])
	return int64(d), nil
}

// Decimal2IP0 transform a decimal IP to x.x.x.x format.
// ref: https://zh.wikipedia.org/wiki/IPv4
func Decimal2IP0(n int64) (ip string, err error) {
	ips := make([]string, 4)
	var b string
	var i int64
	b = strconv.FormatInt(n, 2)
	need := 32 - len(b)
	var j int
	for j = 0; j < need; j++ {
		b = "0" + b
	}
	i, _ = strconv.ParseInt(b[0:8], 2, 64)
	ips[0] = strconv.FormatInt(i, 10)
	i, _ = strconv.ParseInt(b[8:16], 2, 64)
	ips[1] = strconv.FormatInt(i, 10)
	i, _ = strconv.ParseInt(b[16:24], 2, 64)
	ips[2] = strconv.FormatInt(i, 10)
	i, _ = strconv.ParseInt(b[24:32], 2, 64)
	ips[3] = strconv.FormatInt(i, 10)
	ip = strings.Join(ips, ".")
	return
}

// Decimal2IP1 transform a decimal IP to x.x.x.x format.
func Decimal2IP1(n int64) string {
	ui := uint32(n)
	ip := ""
	for i := 0; i < 4; i++ {
		offset := 8 * (3 - i)
		tmp := (ui >> uint32(offset)) & 0xff
		if ip != "" {
			ip += "."
		}
		ip += strconv.Itoa(int(tmp))
	}
	return ip
}

// Decimal2IP transform a decimal IP to x.x.x.x format.
func Decimal2IP(n int64) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, uint32(n))
	return ip.String()
}

// CIDRInfo is the struct of CIDR
type CIDRInfo struct {
	First   string
	Last    string
	Block   int64
	Network string
	Count   int64
}

// CIDR return *CIDRInfo from like this x.x.x.x/x
// ref: http://goo.gl/AEUIi8
func CIDR(cidr string) (c *CIDRInfo, err error) {
	c = new(CIDRInfo)
	cs := strings.Split(cidr, "/")
	if len(cs) != 2 {
		err = errors.New("CIDR Invalid")
		return
	}
	var ipd int64
	ipd, err = IP2Decimal(cs[0])
	if err != nil {
		return
	}
	var ipb string
	ipb = strconv.FormatInt(ipd, 2)
	need := 32 - len(ipb)
	var j int
	for j = 0; j < need; j++ {
		ipb = "0" + ipb
	}

	var n int64
	n, err = strconv.ParseInt(cs[1], 10, 64)
	if err != nil {
		return
	}
	if n < 0 || n > 32 {
		err = errors.New("CIDR Invalid")
		return
	}
	c.Block = n

	var network string
	var networkI int64
	for j = 0; j < int(n); j++ {
		network += "1"
	}
	for j = 0; j < 32-int(n); j++ {
		network += "0"
	}
	networkI, _ = strconv.ParseInt(network, 2, 64)
	network = Decimal2IP(networkI)
	c.Network = network

	first := ipb[0:n]
	var firstI int64
	for j = 0; j < 32-int(n); j++ {
		first = first + "0"
	}
	firstI, _ = strconv.ParseInt(first, 2, 64)
	first = Decimal2IP(firstI)
	c.First = first

	last := ipb[0:n]
	var lastI int64
	for j = 0; j < 32-int(n); j++ {
		last = last + "1"
	}
	lastI, _ = strconv.ParseInt(last, 2, 64)
	last = Decimal2IP(lastI)
	c.Last = last

	c.Count = lastI - firstI + 1
	return
}
