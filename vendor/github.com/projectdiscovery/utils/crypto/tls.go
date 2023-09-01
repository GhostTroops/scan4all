package cryptoutil

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
)

// TLSData contains the relevant Transport Layer Security information
type TLSData struct {
	TLSVersion               string   `json:"tls_version,omitempty"`
	CipherSuite              string   `json:"cipher_suite,omitempty"`
	ExtensionServerName      string   `json:"extension_server_name,omitempty"`
	DNSNames                 []string `json:"dns_names,omitempty"`
	Emails                   []string `json:"emails,omitempty"`
	CommonName               []string `json:"common_name,omitempty"`
	Organization             []string `json:"organization,omitempty"`
	IssuerCommonName         []string `json:"issuer_common_name,omitempty"`
	IssuerOrg                []string `json:"issuer_organization,omitempty"`
	FingerprintSHA256        string   `json:"fingerprint_sha256,omitempty"`
	FingerprintSHA256OpenSSL string   `json:"fingerprint_sha256_openssl,omitempty"`
}

// TLSGrab fills the TLSData
func TLSGrab(c *tls.ConnectionState) *TLSData {
	if c != nil {
		var tlsdata TLSData
		// Only PeerCertificates[0] contains useful information
		cert := c.PeerCertificates[0]
		tlsdata.DNSNames = append(tlsdata.DNSNames, cert.DNSNames...)
		tlsdata.Emails = append(tlsdata.Emails, cert.EmailAddresses...)
		tlsdata.CommonName = append(tlsdata.CommonName, cert.Subject.CommonName)
		tlsdata.Organization = append(tlsdata.Organization, cert.Subject.Organization...)
		tlsdata.IssuerOrg = append(tlsdata.IssuerOrg, cert.Issuer.Organization...)
		tlsdata.IssuerCommonName = append(tlsdata.IssuerCommonName, cert.Issuer.CommonName)
		tlsdata.ExtensionServerName = c.ServerName
		if v, ok := tlsVersionStringMap[c.Version]; ok {
			tlsdata.TLSVersion = v
		}
		if v, ok := tlsCipherStringMap[c.CipherSuite]; ok {
			tlsdata.CipherSuite = v
		}
		if fingerprintSHA256, err := calculateFingerprints(c); err == nil {
			tlsdata.FingerprintSHA256 = asHex(fingerprintSHA256)
			tlsdata.FingerprintSHA256OpenSSL = asOpenSSL(fingerprintSHA256)
		}
		return &tlsdata
	}
	return nil
}

func calculateFingerprints(c *tls.ConnectionState) (fingerprintSHA256 []byte, err error) {
	if len(c.PeerCertificates) == 0 {
		err = errors.New("no certificates found")
		return
	}

	cert := c.PeerCertificates[0]
	dataSHA256 := sha256.Sum256(cert.Raw)
	fingerprintSHA256 = dataSHA256[:]
	return
}

func asOpenSSL(b []byte) string {
	var buf bytes.Buffer
	for i, f := range b {
		if i > 0 {
			fmt.Fprintf(&buf, ":")
		}
		fmt.Fprintf(&buf, "%02X", f)
	}
	return buf.String()
}

func asHex(b []byte) string {
	return hex.EncodeToString(b)
}

var tlsVersionStringMap = map[uint16]string{
	0x0300: "SSL30",
	0x0301: "TLS10",
	0x0302: "TLS11",
	0x0303: "TLS12",
	0x0304: "TLS13",
}

var tlsCipherStringMap = map[uint16]string{
	0x0005: "TLS_RSA_WITH_RC4_128_SHA",
	0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0xc007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	0xc009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0xc00a: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0xc011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	0xc012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0xc023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0x5600: "TLS_FALLBACK_SCSV",
}
