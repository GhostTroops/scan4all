package jarm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"net"
	"strings"
)

/*
	MIT License

	Copyright (c) 2018-2022 Rumble, Inc

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.

*/

// IPv42UInt converts IPv4 addresses to unsigned integers
func IPv42UInt(ips string) (uint32, error) {
	ip := net.ParseIP(ips)
	if ip == nil {
		return 0, errors.New("invalid IPv4 address")
	}
	ip = ip.To4()
	return binary.BigEndian.Uint32(ip), nil
}

// UInt2IPv4 converts unsigned integers to IPv4 addresses
func UInt2IPv4(ipi uint32) string {
	ipb := make([]byte, 4)
	binary.BigEndian.PutUint32(ipb, ipi)
	ip := net.IP(ipb)
	return ip.String()
}

// AddressesFromCIDR parses a CIDR and writes individual IPs to a channel
func AddressesFromCIDR(cidr string, out chan string, quit chan int) error {
	if len(cidr) == 0 {
		return fmt.Errorf("invalid CIDR: empty")
	}

	// We may receive bare IP addresses, add a mask if needed
	if !strings.Contains(cidr, "/") {
		if strings.Contains(cidr, ":") {
			cidr = cidr + "/128"
		} else {
			cidr = cidr + "/32"
		}
	}

	// Parse CIDR into base address + mask
	_, net, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %s %s", cidr, err.Error())
	}

	// Verify IPv4 for now
	ip4 := net.IP.To4()
	if ip4 == nil {
		return fmt.Errorf("invalid IPv4 CIDR: %s", cidr)
	}

	netBase, err := IPv42UInt(net.IP.String())
	if err != nil {
		return fmt.Errorf("invalid IPv4: %s %s", cidr, err)
	}

	maskOnes, maskTotal := net.Mask.Size()

	// Does not work for IPv6 due to cast to uint32
	netSize := uint32(math.Pow(2, float64(maskTotal-maskOnes)))
	curBase := netBase
	endBase := netBase + netSize

	// Iterate the range semi-randomly
	randomWalkIPv4Range(curBase, endBase, out, quit)

	return nil
}

// findPrimeOverMin returns a prime int64 of at least min
func findPrimeOverMin(min int64) int64 {
	var randomSeed int64
	for i := 0; ; i++ {
		randomSeed = rand.Int63()
		// ProbablyPrime is 100% accurate for inputs less than 2⁶⁴
		if big.NewInt(randomSeed).ProbablyPrime(1) {
			if randomSeed > min {
				return randomSeed
			}
		}
	}
}

// randomWalkIPv4Range iterates over an IPv4 range using a prime, writing IPs to the output channel
func randomWalkIPv4Range(min uint32, max uint32, out chan string, quit chan int) {
	s := int64(max - min)
	p := findPrimeOverMin(int64(s))
	if s == 0 {
		return
	}

	q := p % s
	for v := int64(0); v < s; v++ {
		ip := UInt2IPv4(min + uint32(q))
		select {
		case <-quit:
			return
		case out <- ip:
			q = (q + p) % s
		}
	}
}
