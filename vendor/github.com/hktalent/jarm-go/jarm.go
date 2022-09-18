package jarm

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
)

//
// jarm-go is a Go implementation of JARM: An active Transport Layer Security (TLS) server fingerprinting tool.
// https://github.com/salesforce/jarm
//

// RandomBytes generates a random byte sequence of the requested length
func RandomBytes(numbytes int) []byte {
	randBytes := make([]byte, numbytes)
	binary.Read(crand.Reader, binary.BigEndian, &randBytes)
	return randBytes
}

// JarmProbeOptions specifies the parameters for a single probe
type JarmProbeOptions struct {
	Hostname       string
	Port           int
	Version        int
	Ciphers        string
	CipherOrder    string
	Grease         string
	ALPN           string
	V13Mode        string
	ExtensionOrder string
}

// GetProbes returns the standard set of JARM probes in the correct order
func GetProbes(hostname string, port int) []JarmProbeOptions {
	tls12Forward := JarmProbeOptions{Hostname: hostname, Port: port, Version: tls.VersionTLS12, Ciphers: "ALL", CipherOrder: "FORWARD", Grease: "NO_GREASE", ALPN: "ALPN", V13Mode: "1.2_SUPPORT", ExtensionOrder: "REVERSE"}
	tls12Reverse := JarmProbeOptions{Hostname: hostname, Port: port, Version: tls.VersionTLS12, Ciphers: "ALL", CipherOrder: "REVERSE", Grease: "NO_GREASE", ALPN: "ALPN", V13Mode: "1.2_SUPPORT", ExtensionOrder: "FORWARD"}
	tls12TopHalf := JarmProbeOptions{Hostname: hostname, Port: port, Version: tls.VersionTLS12, Ciphers: "ALL", CipherOrder: "TOP_HALF", Grease: "NO_GREASE", ALPN: "NO_SUPPORT", V13Mode: "NO_SUPPORT", ExtensionOrder: "FORWARD"}
	tls12BottomHalf := JarmProbeOptions{Hostname: hostname, Port: port, Version: tls.VersionTLS12, Ciphers: "ALL", CipherOrder: "BOTTOM_HALF", Grease: "NO_GREASE", ALPN: "RARE_ALPN", V13Mode: "NO_SUPPORT", ExtensionOrder: "FORWARD"}
	tls12MiddleOut := JarmProbeOptions{Hostname: hostname, Port: port, Version: tls.VersionTLS12, Ciphers: "ALL", CipherOrder: "MIDDLE_OUT", Grease: "GREASE", ALPN: "RARE_ALPN", V13Mode: "NO_SUPPORT", ExtensionOrder: "REVERSE"}
	tls11Forward := JarmProbeOptions{Hostname: hostname, Port: port, Version: tls.VersionTLS11, Ciphers: "ALL", CipherOrder: "FORWARD", Grease: "NO_GREASE", ALPN: "ALPN", V13Mode: "NO_SUPPORT", ExtensionOrder: "FORWARD"}
	tls13Forward := JarmProbeOptions{Hostname: hostname, Port: port, Version: tls.VersionTLS13, Ciphers: "ALL", CipherOrder: "FORWARD", Grease: "NO_GREASE", ALPN: "ALPN", V13Mode: "1.3_SUPPORT", ExtensionOrder: "REVERSE"}
	tls13Reverse := JarmProbeOptions{Hostname: hostname, Port: port, Version: tls.VersionTLS13, Ciphers: "ALL", CipherOrder: "REVERSE", Grease: "NO_GREASE", ALPN: "ALPN", V13Mode: "1.3_SUPPORT", ExtensionOrder: "FORWARD"}
	tls13Invalid := JarmProbeOptions{Hostname: hostname, Port: port, Version: tls.VersionTLS13, Ciphers: "NO1.3", CipherOrder: "FORWARD", Grease: "NO_GREASE", ALPN: "ALPN", V13Mode: "1.3_SUPPORT", ExtensionOrder: "FORWARD"}
	tls13MiddleOut := JarmProbeOptions{Hostname: hostname, Port: port, Version: tls.VersionTLS13, Ciphers: "ALL", CipherOrder: "MIDDLE_OUT", Grease: "GREASE", ALPN: "ALPN", V13Mode: "1.3_SUPPORT", ExtensionOrder: "REVERSE"}

	return []JarmProbeOptions{
		tls12Forward, tls12Reverse, tls12TopHalf, tls12BottomHalf, tls12MiddleOut, tls11Forward, tls13Forward, tls13Reverse, tls13Invalid, tls13MiddleOut,
	}
}

// GetUint16Bytes returns the 16-bit big endian version of an integer
func GetUint16Bytes(v int) []byte {
	elen := make([]byte, 2)
	binary.BigEndian.PutUint16(elen[:], uint16(v))
	return elen
}

// RandomGrease returns a randomly chosen grease value
func RandomGrease() []byte {
	var rnd = byte(rand.Int31() % 16)
	return []byte{0x0a + (rnd << 4), 0x0a + (rnd << 4)}
}

// BuildProbe creates client hello packet for the probe
func BuildProbe(details JarmProbeOptions) []byte {
	payload := []byte{0x16}
	hello := []byte{}

	switch details.Version {
	case tls.VersionTLS13:
		payload = append(payload, 0x03, 0x01)
		hello = append(hello, 0x03, 0x03)
	case tls.VersionSSL30:
		payload = append(payload, 0x03, 0x00)
		hello = append(hello, 0x03, 0x00)
	case tls.VersionTLS10:
		payload = append(payload, 0x03, 0x01)
		hello = append(hello, 0x03, 0x01)
	case tls.VersionTLS11:
		payload = append(payload, 0x03, 0x02)
		hello = append(hello, 0x03, 0x02)
	case tls.VersionTLS12:
		payload = append(payload, 0x03, 0x03)
		hello = append(hello, 0x03, 0x03)
	}

	hello = append(hello, RandomBytes(32)...)

	sessionID := RandomBytes(32)
	hello = append(hello, byte(len(sessionID)))
	hello = append(hello, sessionID...)

	cipherChoice := GetCiphers(details)

	hello = append(hello, GetUint16Bytes(len(cipherChoice))...)

	hello = append(hello, cipherChoice...)

	hello = append(hello, 0x01)
	hello = append(hello, 0x00)
	hello = append(hello, GetExtensions(details)...)

	innerLength := []byte{0x00}
	innerLength = append(innerLength, GetUint16Bytes(len(hello))...)

	handshakeProtocol := []byte{0x01}
	handshakeProtocol = append(handshakeProtocol, innerLength...)
	handshakeProtocol = append(handshakeProtocol, hello...)

	outerLength := GetUint16Bytes(len(handshakeProtocol))

	payload = append(payload, outerLength...)

	payload = append(payload, handshakeProtocol...)

	return payload
}

// GetCiphers returns the cipher array for a given probe
func GetCiphers(details JarmProbeOptions) []byte {
	ciphers := [][]byte{}

	if details.Ciphers == "ALL" {
		ciphers = [][]byte{
			{0x00, 0x16}, {0x00, 0x33}, {0x00, 0x67}, {0xc0, 0x9e}, {0xc0, 0xa2}, {0x00, 0x9e}, {0x00, 0x39}, {0x00, 0x6b},
			{0xc0, 0x9f}, {0xc0, 0xa3}, {0x00, 0x9f}, {0x00, 0x45}, {0x00, 0xbe}, {0x00, 0x88}, {0x00, 0xc4}, {0x00, 0x9a},
			{0xc0, 0x08}, {0xc0, 0x09}, {0xc0, 0x23}, {0xc0, 0xac}, {0xc0, 0xae}, {0xc0, 0x2b}, {0xc0, 0x0a}, {0xc0, 0x24},
			{0xc0, 0xad}, {0xc0, 0xaf}, {0xc0, 0x2c}, {0xc0, 0x72}, {0xc0, 0x73}, {0xcc, 0xa9}, {0x13, 0x02}, {0x13, 0x01},
			{0xcc, 0x14}, {0xc0, 0x07}, {0xc0, 0x12}, {0xc0, 0x13}, {0xc0, 0x27}, {0xc0, 0x2f}, {0xc0, 0x14}, {0xc0, 0x28},
			{0xc0, 0x30}, {0xc0, 0x60}, {0xc0, 0x61}, {0xc0, 0x76}, {0xc0, 0x77}, {0xcc, 0xa8}, {0x13, 0x05}, {0x13, 0x04},
			{0x13, 0x03}, {0xcc, 0x13}, {0xc0, 0x11}, {0x00, 0x0a}, {0x00, 0x2f}, {0x00, 0x3c}, {0xc0, 0x9c}, {0xc0, 0xa0},
			{0x00, 0x9c}, {0x00, 0x35}, {0x00, 0x3d}, {0xc0, 0x9d}, {0xc0, 0xa1}, {0x00, 0x9d}, {0x00, 0x41}, {0x00, 0xba},
			{0x00, 0x84}, {0x00, 0xc0}, {0x00, 0x07}, {0x00, 0x04}, {0x00, 0x05},
		}
	} else if details.Ciphers == "NO1.3" {
		ciphers = [][]byte{
			{0x00, 0x16}, {0x00, 0x33}, {0x00, 0x67}, {0xc0, 0x9e}, {0xc0, 0xa2}, {0x00, 0x9e}, {0x00, 0x39}, {0x00, 0x6b},
			{0xc0, 0x9f}, {0xc0, 0xa3}, {0x00, 0x9f}, {0x00, 0x45}, {0x00, 0xbe}, {0x00, 0x88}, {0x00, 0xc4}, {0x00, 0x9a},
			{0xc0, 0x08}, {0xc0, 0x09}, {0xc0, 0x23}, {0xc0, 0xac}, {0xc0, 0xae}, {0xc0, 0x2b}, {0xc0, 0x0a}, {0xc0, 0x24},
			{0xc0, 0xad}, {0xc0, 0xaf}, {0xc0, 0x2c}, {0xc0, 0x72}, {0xc0, 0x73}, {0xcc, 0xa9}, {0xcc, 0x14}, {0xc0, 0x07},
			{0xc0, 0x12}, {0xc0, 0x13}, {0xc0, 0x27}, {0xc0, 0x2f}, {0xc0, 0x14}, {0xc0, 0x28}, {0xc0, 0x30}, {0xc0, 0x60},
			{0xc0, 0x61}, {0xc0, 0x76}, {0xc0, 0x77}, {0xcc, 0xa8}, {0xcc, 0x13}, {0xc0, 0x11}, {0x00, 0x0a}, {0x00, 0x2f},
			{0x00, 0x3c}, {0xc0, 0x9c}, {0xc0, 0xa0}, {0x00, 0x9c}, {0x00, 0x35}, {0x00, 0x3d}, {0xc0, 0x9d}, {0xc0, 0xa1},
			{0x00, 0x9d}, {0x00, 0x41}, {0x00, 0xba}, {0x00, 0x84}, {0x00, 0xc0}, {0x00, 0x07}, {0x00, 0x04}, {0x00, 0x05},
		}
	}

	if details.CipherOrder != "FORWARD" {
		ciphers = MungCiphers(ciphers, details.CipherOrder)
	}

	if details.Grease == "GREASE" {
		ciphers = append([][]byte{RandomGrease()}, ciphers...)
	}

	payload := []byte{}
	for _, cipher := range ciphers {
		payload = append(payload, cipher...)
	}
	return payload
}

// MungCipher reorders the cipher list based on the probe settings
func MungCiphers(ciphers [][]byte, request string) [][]byte {
	output := [][]byte{}
	cipherLen := len(ciphers)

	if request == "REVERSE" {
		for i := 1; i <= cipherLen; i++ {
			output = append(output, ciphers[cipherLen-i])
		}
		return output
	}

	if request == "BOTTOM_HALF" {
		if cipherLen%2 == 1 {
			return ciphers[(cipherLen/2)+1:]
		}
		return ciphers[(cipherLen / 2):]
	}

	if request == "TOP_HALF" {
		if cipherLen%2 == 1 {
			output = append(output, ciphers[(cipherLen/2)])
		}

		for _, m := range MungCiphers(MungCiphers(ciphers, "REVERSE"), "BOTTOM_HALF") {
			output = append(output, m)
		}
		return output
	}

	if request == "MIDDLE_OUT" {
		middle := int(cipherLen / 2)
		if cipherLen%2 == 1 {
			output = append(output, ciphers[middle])
			for i := 1; i <= middle; i++ {
				output = append(output, ciphers[middle+i])
				output = append(output, ciphers[middle-i])
			}
		} else {
			for i := 1; i <= middle; i++ {
				output = append(output, ciphers[middle-1+i])
				output = append(output, ciphers[middle-i])
			}
		}
		return output
	}

	return output
}

// ExtGetServerName returns an encoded server name extension
func ExtGetServerName(name string) []byte {
	esni := []byte{0x00, 0x00}
	esni = append(esni, GetUint16Bytes(len(name)+5)...)
	esni = append(esni, GetUint16Bytes(len(name)+3)...)
	esni = append(esni, 0x00)
	esni = append(esni, GetUint16Bytes(len(name))...)
	esni = append(esni, []byte(name)...)
	return esni
}

// ExtGetALPN returns an encoded ALPN extension
func ExtGetALPN(details JarmProbeOptions) []byte {
	ext := []byte{0x00, 0x10}
	alpns := [][]byte{}

	if details.ALPN == "RARE_ALPN" {
		// All ALPN except H2 and HTTP/1.1
		alpns = [][]byte{
			{0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x30, 0x2e, 0x39},
			{0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x30},
			{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x31},
			{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x32},
			{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33},
			{0x03, 0x68, 0x32, 0x63},
			{0x02, 0x68, 0x71},
		}
	} else {
		// All APLN from weakest to strongest
		alpns = [][]byte{
			{0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x30, 0x2e, 0x39},
			{0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x30},
			{0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31},
			{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x31},
			{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x32},
			{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33},
			{0x02, 0x68, 0x32},
			{0x03, 0x68, 0x32, 0x63},
			{0x02, 0x68, 0x71},
		}
	}
	if details.ExtensionOrder != "FORWARD" {
		alpns = MungCiphers(alpns, details.ExtensionOrder)
	}

	allALPNs := []byte{}
	for _, a := range alpns {
		allALPNs = append(allALPNs, a...)
	}

	ext = append(ext, GetUint16Bytes(len(allALPNs)+2)...)
	ext = append(ext, GetUint16Bytes(len(allALPNs))...)
	ext = append(ext, allALPNs...)
	return ext
}

// ExtGetKeyShare returns an encoded KeyShare extension
func ExtGetKeyShare(grease bool) []byte {
	ext := []byte{0x00, 0x33}
	shareExt := []byte{}
	if grease {
		shareExt = RandomGrease()
		shareExt = append(shareExt, 0x00, 0x01, 0x00)
	}

	shareExt = append(shareExt, 0x00, 0x1d)
	shareExt = append(shareExt, 0x00, 0x20)
	shareExt = append(shareExt, RandomBytes(32)...)
	secondLength := len(shareExt)
	firstLength := secondLength + 2
	ext = append(ext, GetUint16Bytes(firstLength)...)
	ext = append(ext, GetUint16Bytes(secondLength)...)
	ext = append(ext, shareExt...)
	return ext
}

// ExtGetSupportedVersions returns an encoded SupportedVersions extension
func ExtGetSupportedVersions(details JarmProbeOptions, grease bool) []byte {
	tlsVersions := [][]byte{}
	if details.V13Mode == "1.2_SUPPORT" {
		tlsVersions = append(tlsVersions, []byte{0x03, 0x01})
		tlsVersions = append(tlsVersions, []byte{0x03, 0x02})
		tlsVersions = append(tlsVersions, []byte{0x03, 0x03})
	} else {
		tlsVersions = append(tlsVersions, []byte{0x03, 0x01})
		tlsVersions = append(tlsVersions, []byte{0x03, 0x02})
		tlsVersions = append(tlsVersions, []byte{0x03, 0x03})
		tlsVersions = append(tlsVersions, []byte{0x03, 0x04})
	}
	if details.ExtensionOrder != "FORWARD" {
		tlsVersions = MungCiphers(tlsVersions, details.ExtensionOrder)
	}

	ver := []byte{}
	if grease {
		ver = append(ver, RandomGrease()...)
	}
	for _, v := range tlsVersions {
		ver = append(ver, v...)
	}

	ext := []byte{0x00, 0x2b}
	ext = append(ext, GetUint16Bytes(len(ver)+1)...)
	ext = append(ext, byte(len(ver)))
	ext = append(ext, ver...)
	return ext
}

// GetExtensions returns the encoded extensions for a given probe
func GetExtensions(details JarmProbeOptions) []byte {
	allExtensions := []byte{}
	grease := false

	if details.Grease == "GREASE" {
		allExtensions = append(allExtensions, RandomGrease()...)
		allExtensions = append(allExtensions, 0x00, 0x00)
		grease = true
	}

	allExtensions = append(allExtensions, ExtGetServerName(details.Hostname)...)
	allExtensions = append(allExtensions, 0x00, 0x17, 0x00, 0x00)
	allExtensions = append(allExtensions, 0x00, 0x01, 0x00, 0x01, 0x01)
	allExtensions = append(allExtensions, 0xff, 0x01, 0x00, 0x01, 0x00)
	allExtensions = append(allExtensions, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19)
	allExtensions = append(allExtensions, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00)
	allExtensions = append(allExtensions, 0x00, 0x23, 0x00, 0x00)
	allExtensions = append(allExtensions, ExtGetALPN(details)...)
	allExtensions = append(allExtensions, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01)
	allExtensions = append(allExtensions, ExtGetKeyShare(grease)...)
	allExtensions = append(allExtensions, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01)

	if details.Version == tls.VersionTLS13 || details.V13Mode == "1.2_SUPPORT" {
		allExtensions = append(allExtensions, ExtGetSupportedVersions(details, grease)...)
	}

	extensions := GetUint16Bytes(len(allExtensions))
	extensions = append(extensions, allExtensions...)
	return extensions
}

// ParseServerHello returns the raw fingerprint for a server hello response
func ParseServerHello(data []byte, details JarmProbeOptions) (string, error) {
	if len(data) == 0 {
		return "|||", nil
	}

	// Alert indicates a failed handshake
	if data[0] == 21 {
		return "|||", nil
	}

	// Not a Server Hello response
	if !(data[0] == 22 && len(data) > 5 && data[5] == 2) {
		return "|||", nil
	}
	// server_hello_length
	serverHelloLength := int(binary.BigEndian.Uint16(data[3:5]))

	// Too short
	if len(data) < 44 {
		return "|||", nil
	}

	counter := int(data[43])
	cipherOffset := counter + 44
	if len(data) < (cipherOffset + 2) {
		return "|||", nil
	}

	serverCip := hex.EncodeToString(data[cipherOffset : cipherOffset+2])
	serverVer := hex.EncodeToString(data[9:11])
	serverExt := ExtractExtensionInfo(data, counter, serverHelloLength)

	return fmt.Sprintf("%s|%s|%s", serverCip, serverVer, serverExt), nil
}

// ExtractExtensionInfo returns parsed extension information from a server hello response
func ExtractExtensionInfo(data []byte, offset int, serverHelloLength int) string {
	if len(data) < 85 || len(data) < (offset+53) {
		return "|"
	}

	if data[offset+47] == 11 {
		return "|"
	}

	if offset+42 >= serverHelloLength {
		return "|"
	}

	if bytes.Equal(data[offset+50:offset+53], []byte{0x0e, 0xac, 0x0b}) ||
		bytes.Equal(data[82:85], []byte{0x0f, 0xf0, 0x0b}) {
		return "|"
	}

	ecnt := offset + 49
	elen := int(binary.BigEndian.Uint16(data[offset+47 : offset+49]))
	emax := elen + ecnt - 1

	etypes := [][]byte{}
	evals := [][]byte{}

	for ecnt < emax {
		if len(data) < ecnt+2 {
			break
		}

		if len(data) < ecnt+4 {
			break
		}
		etypes = append(etypes, data[ecnt:ecnt+2])

		extlen := int(binary.BigEndian.Uint16(data[ecnt+2 : ecnt+4]))
		if len(data) < ecnt+4+extlen {
			break
		}

		if extlen == 0 {
			evals = append(evals, []byte{})
		} else {
			evals = append(evals, data[ecnt+4:ecnt+4+extlen])
		}
		ecnt = ecnt + extlen + 4
	}

	alpn := string(ExtractExtensionType([]byte{0x00, 0x10}, etypes, evals))
	etypeList := []string{}
	for _, t := range etypes {
		etypeList = append(etypeList, hex.EncodeToString(t))
	}
	return alpn + "|" + strings.Join(etypeList, "-")
}

// ExtractExtensionType returns the stringified value of a given extension type
func ExtractExtensionType(ext []byte, etypes [][]byte, evals [][]byte) string {
	for i := 0; i < len(etypes); i++ {
		if !bytes.Equal(ext, etypes[i]) {
			continue
		}
		if i >= len(evals) {
			continue
		}
		eval := evals[i]
		if len(eval) < 4 {
			continue
		}
		if bytes.Equal(ext, []byte{0x00, 0x10}) {
			return string(eval[3:])
		}
		return string(hex.EncodeToString(eval))
	}
	return ""
}

// ZeroHash represents an empty JARM hash
var ZeroHash = "00000000000000000000000000000000000000000000000000000000000000"

// RawHashToFuzzyHash converts a raw hash to a JARM hash
func RawHashToFuzzyHash(raw string) string {
	if raw == "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||" {
		return ZeroHash
	}
	fhash := ""
	alpex := ""
	for _, handshake := range strings.Split(raw, ",") {
		comp := strings.Split(handshake, "|")
		if len(comp) != 4 {
			return ZeroHash
		}
		fhash = fhash + ExtractCipherBytes(comp[0])
		fhash = fhash + ExtractVersionByte(comp[1])
		alpex = alpex + comp[2]
		alpex = alpex + comp[3]
	}
	hash256 := sha256.Sum256([]byte(alpex))
	fhash += hex.EncodeToString(hash256[:])[0:32]
	return fhash
}

var cipherListOrder = [][]byte{
	{0x00, 0x04}, {0x00, 0x05}, {0x00, 0x07}, {0x00, 0x0a}, {0x00, 0x16}, {0x00, 0x2f}, {0x00, 0x33}, {0x00, 0x35},
	{0x00, 0x39}, {0x00, 0x3c}, {0x00, 0x3d}, {0x00, 0x41}, {0x00, 0x45}, {0x00, 0x67}, {0x00, 0x6b}, {0x00, 0x84},
	{0x00, 0x88}, {0x00, 0x9a}, {0x00, 0x9c}, {0x00, 0x9d}, {0x00, 0x9e}, {0x00, 0x9f}, {0x00, 0xba}, {0x00, 0xbe},
	{0x00, 0xc0}, {0x00, 0xc4}, {0xc0, 0x07}, {0xc0, 0x08}, {0xc0, 0x09}, {0xc0, 0x0a}, {0xc0, 0x11}, {0xc0, 0x12},
	{0xc0, 0x13}, {0xc0, 0x14}, {0xc0, 0x23}, {0xc0, 0x24}, {0xc0, 0x27}, {0xc0, 0x28}, {0xc0, 0x2b}, {0xc0, 0x2c},
	{0xc0, 0x2f}, {0xc0, 0x30}, {0xc0, 0x60}, {0xc0, 0x61}, {0xc0, 0x72}, {0xc0, 0x73}, {0xc0, 0x76}, {0xc0, 0x77},
	{0xc0, 0x9c}, {0xc0, 0x9d}, {0xc0, 0x9e}, {0xc0, 0x9f}, {0xc0, 0xa0}, {0xc0, 0xa1}, {0xc0, 0xa2}, {0xc0, 0xa3},
	{0xc0, 0xac}, {0xc0, 0xad}, {0xc0, 0xae}, {0xc0, 0xaf}, {0xcc, 0x13}, {0xcc, 0x14}, {0xcc, 0xa8}, {0xcc, 0xa9},
	{0x13, 0x01}, {0x13, 0x02}, {0x13, 0x03}, {0x13, 0x04}, {0x13, 0x05},
}

// ExtractCipherBytes converts a selected cipher to an index of the known cipher list
func ExtractCipherBytes(c string) string {
	if c == "" {
		return "00"
	}
	count := 1
	for _, cipher := range cipherListOrder {
		if hex.EncodeToString(cipher) == c {
			break
		}
		count = count + 1
	}
	return fmt.Sprintf("%.2x", count)
}

// ExtractVersionByte returns 1-byte hex string representing the negotiated version
func ExtractVersionByte(c string) string {
	if c == "" || len(c) < 4 {
		return "0"
	}
	ival, err := strconv.Atoi(c[3:4])
	if err != nil {
		return "0"
	}
	return string(byte(0x61 + ival))
}
