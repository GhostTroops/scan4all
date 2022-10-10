package clients

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"math"
	"strings"
	"time"

	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	zpkix "github.com/zmap/zcrypto/x509/pkix"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/stringsutil"
)

// Implementation is an interface implemented by TLSX client
type Implementation interface {
	// Connect connects to a host and grabs the response data
	ConnectWithOptions(hostname, ip, port string, options ConnectOptions) (*Response, error)
	// SupportedTLSVersions returns the list of supported tls versions
	SupportedTLSVersions() ([]string, error)
	// SupportedTLSCiphers returns the list of supported tls ciphers
	SupportedTLSCiphers() ([]string, error)
}

// Options contains configuration options for tlsx client
type Options struct {
	// OutputFile is the file to write output to
	OutputFile string
	// Inputs is a list of inputs to process
	Inputs goflags.StringSlice
	// InputList is the list of inputs to process
	InputList string
	// ServerName is the optional server-name for tls connection
	ServerName goflags.StringSlice
	// Verbose enables display of verbose output
	Verbose bool
	// Version shows the version of the program
	Version bool
	// JSON enables display of JSON output
	JSON bool
	// TLSChain enables printing TLS chain information to output
	TLSChain bool
	// AllCiphers enables sending all ciphers as client
	AllCiphers bool
	// ProbeStatus enables writing of errors with json output
	ProbeStatus bool
	// CertsOnly enables early SSL termination using ztls flag
	CertsOnly bool
	// RespOnly displays TLS respones only in CLI output
	RespOnly bool
	// Silent enables silent output display
	Silent bool
	// NoColor disables coloring of CLI output
	NoColor bool
	// Retries is the number of times to retry TLS connection
	Retries int
	// Timeout is the number of seconds to wait for connection
	Timeout int
	// Concurrency is the number of concurrent threads to process
	Concurrency int
	// Port is the ports to make request to
	Ports goflags.StringSlice
	// Ciphers is a list of custom ciphers to use for connection
	Ciphers goflags.StringSlice
	// CACertificate is the CA certificate for connection
	CACertificate string
	// MinVersion is the minimum tls version that is acceptable
	MinVersion string
	// MaxVersion is the maximum tls version that is acceptable
	MaxVersion string
	// Resolvers contains custom resolvers for the tlsx client
	Resolvers goflags.StringSlice
	// ScanMode is the tls connection mode to use
	ScanMode string
	// VerifyServerCertificate enables optional verification of server certificates
	VerifyServerCertificate bool

	// Begin List of probes for tlsx

	// SAN displays Subject Alternative Names
	SAN bool
	// CN displays Subject Common Name
	CN bool
	// SO displays Subject Organization Name
	SO bool
	// TLSVersion displays used TLS version
	TLSVersion bool
	// Cipher displays used cipher
	Cipher bool
	// Expired displays validity of TLS certificate
	Expired bool
	// SelfSigned displays if cert is self-signed
	SelfSigned bool
	// MisMatched displays if the cert is mismatched
	MisMatched bool
	// Hash is the hash to display for certificate
	Hash string
	// Jarm calculate jarm fingerprinting with multiple probes
	Jarm bool
	// Cert displays certificate in pem format
	Cert bool
	// Ja3 displays ja3 fingerprint hash
	Ja3 bool
	// Scan all IP's
	ScanAllIPs bool
	// IP Version to use for scanning
	IPVersion goflags.StringSlice
	// WildcardCertCheck enables wildcard certificate check
	WildcardCertCheck bool
	// TlsVersionsEnum enumerates supported tls versions
	TlsVersionsEnum bool
	// TlsCiphersEnum enumerates supported ciphers per TLS protocol
	TlsCiphersEnum bool

	// Fastdialer is a fastdialer dialer instance
	Fastdialer *fastdialer.Dialer
}

// Response is the response returned for a TLS grab event
type Response struct {
	// Timestamp is the timestamp for certificate response
	Timestamp *time.Time `json:"timestamp,omitempty"`
	// Host is the host to make request to
	Host string `json:"host"`
	// IP is the IP address the request was made to
	IP string `json:"ip,omitempty"`
	// Port is the port to make request to
	Port string `json:"port"`
	// ProbeStatus is false if the tls probe failed
	ProbeStatus bool `json:"probe_status"`
	// Error is the optional error for tls request included
	// with errors_json flag.
	Error string `json:"error,omitempty"`
	// Version is the tls version responded by the server
	Version string `json:"tls_version,omitempty"`
	// Cipher is the cipher for the tls request
	Cipher string `json:"cipher,omitempty"`
	// CertificateResponse is the leaf certificate embedded in json
	*CertificateResponse `json:",inline"`
	// TLSConnection is the client used for TLS connection
	// when ran using scan-mode auto.
	TLSConnection string `json:"tls_connection,omitempty"`
	// Chain is the chain of certificates
	Chain       []*CertificateResponse `json:"chain,omitempty"`
	JarmHash    string                 `json:"jarm_hash,omitempty"`
	Ja3Hash     string                 `json:"ja3_hash,omitempty"`
	ServerName  string                 `json:"sni,omitempty"`
	VersionEnum []string               `json:"version_enum,omitempty"`
	TlsCiphers  []TlsCiphers           `json:"cipher_enum,omitempty"`
}

type TlsCiphers struct {
	Version string   `json:"version,omitempty"`
	Ciphers []string `json:"ciphers,omitempty"`
}

// CertificateResponse is the response for a certificate
type CertificateResponse struct {
	// Expired specifies whether the certificate has expired
	Expired bool `json:"expired,omitempty"`
	// SelfSigned returns true if the certificate is self-signed
	SelfSigned bool `json:"self_signed,omitempty"`
	// MisMatched returns true if the certificate is mismatched
	MisMatched bool `json:"mismatched,omitempty"`
	// NotBefore is the not-before time for certificate
	NotBefore time.Time `json:"not_before,omitempty"`
	// NotAfter is the not-after time for certificate
	NotAfter time.Time `json:"not_after,omitempty"`
	// SubjectDN is the distinguished name for cert
	SubjectDN string `json:"subject_dn,omitempty"`
	// SubjectCN is the common name for cert
	SubjectCN string `json:"subject_cn,omitempty"`
	// SubjectOrg is the organization for cert subject
	SubjectOrg []string `json:"subject_org,omitempty"`
	// SubjectAN is a list of Subject Alternative Names for the certificate
	SubjectAN []string `json:"subject_an,omitempty"`
	// IssuerDN is the distinguished name for cert
	IssuerDN string `json:"issuer_dn,omitempty"`
	// IssuerCN is the common name for cert
	IssuerCN string `json:"issuer_cn,omitempty"`
	// IssuerOrg is the organization for cert issuer
	IssuerOrg []string `json:"issuer_org,omitempty"`
	// Emails is a list of Emails for the certificate
	Emails []string `json:"emails,omitempty"`
	// FingerprintHash is the hashes for certificate
	FingerprintHash CertificateResponseFingerprintHash `json:"fingerprint_hash,omitempty"`
	// Certificate is the raw certificate in PEM format
	Certificate string `json:"certificate,omitempty"`
	// WildCardCert is true if tls certificate is a wildcard certificate
	WildCardCert bool `json:"wildcard_certificate,omitempty"`
}

// CertificateDistinguishedName is a distinguished certificate name
type CertificateDistinguishedName struct {
	Country            []string `json:"country,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty"`
	Locality           []string `json:"locality,omitempty"`
	Province           []string `json:"province,omitempty"`
	StreetAddress      []string `json:"street_address,omitempty"`
	CommonName         string   `json:"common_name,omitempty"`
}

// CertificateResponseFingerprintHash is a response for fingerprint hash of cert
type CertificateResponseFingerprintHash struct {
	// MD5 is the md5 hash for certificate
	MD5 string `json:"md5,omitempty"`
	// SHA1 is the sha1 hash for certificate
	SHA1 string `json:"sha1,omitempty"`
	// SHA256 is the sha256 hash for certificate
	SHA256 string `json:"sha256,omitempty"`
}

// MD5Fingerprint creates a fingerprint of data using the MD5 hash algorithm.
func MD5Fingerprint(data []byte) string {
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}

// SHA1Fingerprint creates a fingerprint of data using the SHA1 hash algorithm.
func SHA1Fingerprint(data []byte) string {
	sum := sha1.Sum(data)
	return hex.EncodeToString(sum[:])
}

// SHA256Fingerprint creates a fingerprint of data using the SHA256 hash
// algorithm.
func SHA256Fingerprint(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// IsExpired returns true if the certificate has expired
func IsExpired(notAfter time.Time) bool {
	remaining := math.Round(time.Since(notAfter).Seconds())
	return remaining > 0
}

// IsSelfSigned returns true if the certificate is self-signed
//
// follows: https://security.stackexchange.com/a/162263/250973
func IsSelfSigned(authorityKeyID, subjectKeyID []byte) bool {
	if len(authorityKeyID) == 0 || bytes.Equal(authorityKeyID, subjectKeyID) {
		return true
	}
	return false
}

// IsMisMatchedCert returns true if cert names(subject common name + alternative names) does not contain host
func IsMisMatchedCert(host string, alternativeNames []string) bool {
	hostTokens := strings.Split(host, ".")
	for _, alternativeName := range alternativeNames {
		// if not wildcard, return false if name matches the host
		if !strings.Contains(alternativeName, "*") {
			if strings.EqualFold(alternativeName, host) {
				return false
			}
		} else {
			// try to match the wildcard name with host
			nameTokens := strings.Split(alternativeName, ".")
			if len(hostTokens) == len(nameTokens) {
				matched := false
				for i, token := range nameTokens {
					if i == 0 {
						// match leftmost token
						matched = matchWildCardToken(token, hostTokens[i])
						if !matched {
							return true
						}
					} else {
						// match all other tokens
						matched = stringsutil.EqualFoldAny(token, hostTokens[i])
						if !matched {
							return true
						}
					}
				}
				// return false if all the name tokens matched the host tokens
				if matched {
					return false
				}
			}
		}
	}
	return true
}

// matchWildCardToken matches the wildcardName token and host token
func matchWildCardToken(name, host string) bool {
	if strings.Contains(name, "*") {
		nameSubTokens := strings.Split(name, "*")
		if strings.HasPrefix(name, "*") {
			return strings.HasSuffix(host, nameSubTokens[1])
		} else if strings.HasSuffix(name, "*") {
			return strings.HasPrefix(host, nameSubTokens[0])
		} else {
			return strings.HasPrefix(host, nameSubTokens[0]) &&
				strings.HasSuffix(host, nameSubTokens[1])
		}
	}
	return strings.EqualFold(name, host)
}

// IsWildCardCert returns true if the certificate is a wildcard certificate
func IsWildCardCert(names []string) bool {
	for _, name := range names {
		if strings.Contains(name, "*.") {
			return true
		}
	}
	return false
}

// PemEncode encodes a raw certificate to PEM format.
func PemEncode(cert []byte) string {
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
		return ""
	}
	return buf.String()
}

type ConnectOptions struct {
	SNI        string
	VersionTLS string
	Ciphers    []string
}

// ParseASN1DNSequenceWithZpkixOrDefault return the parsed value of ASN1DNSequence or a default string value
func ParseASN1DNSequenceWithZpkixOrDefault(data []byte, defaultValue string) string {
	if value := ParseASN1DNSequenceWithZpkix(data); value != "" {
		return value
	}
	return defaultValue
}

// ParseASN1DNSequenceWithZpkix tries to parse raw ASN1 of a TLS DN with zpkix and
// zasn1 library which includes additional information not parsed by go standard
// library which may be useful.
//
// If the parsing fails, a blank string is returned and the standard library data is used.
func ParseASN1DNSequenceWithZpkix(data []byte) string {
	var rdnSequence zpkix.RDNSequence
	var name zpkix.Name
	if _, err := zasn1.Unmarshal(data, &rdnSequence); err != nil {
		return ""
	}
	name.FillFromRDNSequence(&rdnSequence)
	dnParsedString := name.String()
	return dnParsedString
}
