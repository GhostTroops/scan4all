package ja3

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"

	"github.com/zmap/zcrypto/tls"
)

const (
	dashByte  = byte(45)
	commaByte = byte(44)

	// GREASE values
	// The bitmask covers all GREASE values
	greaseBitmask uint16 = 0x0F0F
)

// TLS extension numbers
const (
	extensionServerName           uint16 = 0
	extensionStatusRequest        uint16 = 5
	extensionSupportedCurves      uint16 = 10
	extensionSupportedPoints      uint16 = 11
	extensionSignatureAlgorithms  uint16 = 13
	extensionALPN                 uint16 = 16
	extensionExtendedMasterSecret uint16 = 23
	extensionSessionTicket        uint16 = 35
	extensionNextProtoNeg         uint16 = 13172 // not IANA assigned
	extensionRenegotiationInfo    uint16 = 0xff01
	extensionExtendedRandom       uint16 = 0x0028 // not IANA assigned
	extensionSCT                  uint16 = 18
	extensionHeartbeat            uint16 = 15
)

// GetJa3SHash returns the JA3 fingerprint hash of the tls client hello.
func GetJa3Hash(clientHello *tls.ClientHello) string {
	byteString := make([]byte, 0)

	// Version
	byteString = strconv.AppendUint(byteString, uint64(clientHello.Version), 10)
	byteString = append(byteString, commaByte)

	// Cipher Suites
	if len(clientHello.CipherSuites) != 0 {
		for _, val := range clientHello.CipherSuites {
			byteString = strconv.AppendUint(byteString, uint64(val), 10)
			byteString = append(byteString, dashByte)
		}
		// Replace last dash with a comma
		byteString[len(byteString)-1] = commaByte
	} else {
		byteString = append(byteString, commaByte)
	}

	// Extensions
	if len(clientHello.ServerName) > 0 {
		byteString = appendExtension(byteString, extensionServerName)
	}

	if clientHello.NextProtoNeg {
		byteString = appendExtension(byteString, extensionNextProtoNeg)
	}

	if clientHello.OcspStapling {
		byteString = appendExtension(byteString, extensionStatusRequest)
	}

	if len(clientHello.SupportedCurves) > 0 {
		byteString = appendExtension(byteString, extensionSupportedCurves)
	}

	if len(clientHello.SupportedPoints) > 0 {
		byteString = appendExtension(byteString, extensionSupportedPoints)
	}

	if clientHello.TicketSupported {
		byteString = appendExtension(byteString, extensionSessionTicket)
	}

	if len(clientHello.SignatureAndHashes) > 0 {
		byteString = appendExtension(byteString, extensionSignatureAlgorithms)
	}

	if clientHello.SecureRenegotiation {
		byteString = appendExtension(byteString, extensionRenegotiationInfo)
	}

	if len(clientHello.AlpnProtocols) > 0 {
		byteString = appendExtension(byteString, extensionALPN)
	}

	if clientHello.HeartbeatSupported {
		byteString = appendExtension(byteString, extensionHeartbeat)
	}

	if len(clientHello.ExtendedRandom) > 0 {
		byteString = appendExtension(byteString, extensionExtendedRandom)
	}

	if clientHello.ExtendedMasterSecret {
		byteString = appendExtension(byteString, extensionExtendedMasterSecret)
	}

	if clientHello.SctEnabled {
		byteString = appendExtension(byteString, extensionSCT)
	}

	if len(clientHello.UnknownExtensions) > 0 {
		for _, ext := range clientHello.UnknownExtensions {
			exType := uint16(ext[0])<<8 | uint16(ext[1])
			byteString = appendExtension(byteString, exType)
		}
	}
	// If dash found replace it with a comma
	if byteString[len(byteString)-1] == dashByte {
		byteString[len(byteString)-1] = commaByte
	} else {
		// else add a comma (no extension present)
		byteString = append(byteString, commaByte)
	}

	// Suppported Elliptic Curves
	if len(clientHello.SupportedCurves) > 0 {
		for _, val := range clientHello.SupportedCurves {
			byteString = strconv.AppendUint(byteString, uint64(val), 10)
			byteString = append(byteString, dashByte)
		}
		// Replace last dash with a comma
		byteString[len(byteString)-1] = commaByte
	} else {
		byteString = append(byteString, commaByte)
	}

	// Elliptic Curve Point Formats
	if len(clientHello.SupportedPoints) > 0 {
		for _, val := range clientHello.SupportedPoints {
			byteString = strconv.AppendUint(byteString, uint64(val), 10)
			byteString = append(byteString, dashByte)
		}
		// Remove last dash
		byteString = byteString[:len(byteString)-1]
	}

	h := md5.Sum(byteString)
	return hex.EncodeToString(h[:])
}

func appendExtension(byteString []byte, exType uint16) []byte {
	// Ignore any GREASE extensions
	if exType&greaseBitmask != 0x0A0A {
		byteString = strconv.AppendUint(byteString, uint64(exType), 10)
		byteString = append(byteString, dashByte)
	}
	return byteString
}
