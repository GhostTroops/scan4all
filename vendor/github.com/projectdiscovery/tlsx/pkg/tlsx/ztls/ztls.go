// Package ztls implements a tls grabbing implementation using
// zmap zcrypto/tls library.
package ztls

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/ztls/ja3"
	"github.com/rs/xid"
	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zcrypto/x509"
)

// Client is a TLS grabbing client using crypto/tls
type Client struct {
	dialer    *fastdialer.Dialer
	tlsConfig *tls.Config
	options   *clients.Options
}

// versionStringToTLSVersion converts tls version string to version
var versionStringToTLSVersion = map[string]uint16{
	"ssl30": tls.VersionSSL30,
	"tls10": tls.VersionTLS10,
	"tls11": tls.VersionTLS11,
	"tls12": tls.VersionTLS12,
}

// versionToTLSVersionString converts tls version to version string
var versionToTLSVersionString = map[uint16]string{
	tls.VersionSSL30: "ssl30",
	tls.VersionTLS10: "tls10",
	tls.VersionTLS11: "tls11",
	tls.VersionTLS12: "tls12",
}

// New creates a new grabbing client using crypto/tls
func New(options *clients.Options) (*Client, error) {
	c := &Client{
		dialer: options.Fastdialer,
		tlsConfig: &tls.Config{
			CertsOnly:          options.CertsOnly,
			MinVersion:         tls.VersionSSL30,
			MaxVersion:         tls.VersionTLS12,
			InsecureSkipVerify: !options.VerifyServerCertificate,
		},
		options: options,
	}

	if options.AllCiphers {
		c.tlsConfig.CipherSuites = AllCiphers
	}
	if len(options.Ciphers) > 0 {
		if customCiphers, err := toZTLSCiphers(options.Ciphers); err != nil {
			return nil, errors.Wrap(err, "could not get ztls ciphers")
		} else {
			c.tlsConfig.CipherSuites = customCiphers
		}
	}
	if options.CACertificate != "" {
		caCert, err := os.ReadFile(options.CACertificate)
		if err != nil {
			return nil, errors.Wrap(err, "could not read ca certificate")
		}
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCert) {
			gologger.Error().Msgf("Could not append parsed ca-cert to config!")
		}
		c.tlsConfig.RootCAs = certPool
	}
	if options.MinVersion != "" {
		version, ok := versionStringToTLSVersion[options.MinVersion]
		if !ok {
			return nil, fmt.Errorf("invalid min version specified: %s", options.MinVersion)
		} else {
			c.tlsConfig.MinVersion = version
		}
	}
	if options.MaxVersion != "" {
		version, ok := versionStringToTLSVersion[options.MaxVersion]
		if !ok {
			return nil, fmt.Errorf("invalid max version specified: %s", options.MaxVersion)
		} else {
			c.tlsConfig.MaxVersion = version
		}
	}
	return c, nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "tls: DialWithDialer timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// Connect connects to a host and grabs the response data
func (c *Client) ConnectWithOptions(hostname, ip, port string, options clients.ConnectOptions) (*clients.Response, error) {
	address := net.JoinHostPort(hostname, port)
	if c.options.ScanAllIPs || len(c.options.IPVersion) > 0 {
		address = net.JoinHostPort(ip, port)
	}
	timeout := time.Duration(c.options.Timeout) * time.Second

	var errChannel chan error
	if timeout != 0 {
		errChannel = make(chan error, 2)
		time.AfterFunc(timeout, func() {
			errChannel <- timeoutError{}
		})
	}

	ctx := context.Background()
	if c.options.Timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	conn, err := c.dialer.Dial(ctx, "tcp", address)
	if err != nil {
		return nil, errors.Wrap(err, "could not connect to address")
	}
	if conn == nil {
		return nil, fmt.Errorf("could not connect to %s", address)
	}
	var resolvedIP string
	if !iputil.IsIP(hostname) {
		resolvedIP = c.dialer.GetDialedIP(hostname)
		if resolvedIP == "" {
			resolvedIP = ip
		}
	}

	config := c.tlsConfig
	if config.ServerName == "" {
		c := config.Clone()
		if options.SNI != "" {
			c.ServerName = options.SNI
		} else if iputil.IsIP(hostname) {
			// using a random sni will return the default server certificate
			c.ServerName = xid.New().String()
		} else {
			c.ServerName = hostname
		}
		config = c
	}

	if options.VersionTLS != "" {
		version, ok := versionStringToTLSVersion[options.VersionTLS]
		if !ok {
			return nil, fmt.Errorf("invalid tls version specified: %s", options.VersionTLS)
		}
		config.MinVersion = version
		config.MaxVersion = version
	}

	if len(options.Ciphers) > 0 {
		customCiphers, err := toZTLSCiphers(options.Ciphers)
		if err != nil {
			return nil, errors.Wrap(err, "could not get tls ciphers")
		}
		c.tlsConfig.CipherSuites = customCiphers
	}

	tlsConn := tls.Client(conn, config)
	if timeout == 0 {
		err = tlsConn.Handshake()
	} else {
		go func() {
			errChannel <- tlsConn.Handshake()
		}()
		err = <-errChannel
	}
	if err == tls.ErrCertsOnly {
		err = nil
	}
	if err != nil {
		conn.Close()
		return nil, errors.Wrap(err, "could not do tls handshake")
	}
	defer tlsConn.Close()

	hl := tlsConn.GetHandshakeLog()

	tlsVersion := versionToTLSVersionString[uint16(hl.ServerHello.Version)]
	tlsCipher := hl.ServerHello.CipherSuite.String()

	now := time.Now()
	response := &clients.Response{
		Timestamp:           &now,
		Host:                hostname,
		IP:                  resolvedIP,
		ProbeStatus:         true,
		Port:                port,
		Version:             tlsVersion,
		Cipher:              tlsCipher,
		TLSConnection:       "ztls",
		CertificateResponse: ConvertCertificateToResponse(c.options, hostname, ParseSimpleTLSCertificate(hl.ServerCertificates.Certificate)),
		ServerName:          config.ServerName,
	}
	if c.options.TLSChain {
		for _, cert := range hl.ServerCertificates.Chain {
			response.Chain = append(response.Chain, ConvertCertificateToResponse(c.options, hostname, ParseSimpleTLSCertificate(cert)))
		}
	}
	if c.options.Ja3 {
		response.Ja3Hash = ja3.GetJa3Hash(hl.ClientHello)
	}
	return response, nil
}

// ParseSimpleTLSCertificate using zcrypto x509
func ParseSimpleTLSCertificate(cert tls.SimpleCertificate) *x509.Certificate {
	parsed, _ := x509.ParseCertificate(cert.Raw)
	return parsed
}

// ConvertCertificateToResponse using zcrypto x509
func ConvertCertificateToResponse(options *clients.Options, hostname string, cert *x509.Certificate) *clients.CertificateResponse {
	if cert == nil {
		return nil
	}
	response := &clients.CertificateResponse{
		SubjectAN:    cert.DNSNames,
		Emails:       cert.EmailAddresses,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Expired:      clients.IsExpired(cert.NotAfter),
		SelfSigned:   clients.IsSelfSigned(cert.AuthorityKeyId, cert.SubjectKeyId),
		MisMatched:   clients.IsMisMatchedCert(hostname, append(cert.DNSNames, cert.Subject.CommonName)),
		WildCardCert: clients.IsWildCardCert(append(cert.DNSNames, cert.Subject.CommonName)),
		IssuerDN:     cert.Issuer.String(),
		IssuerCN:     cert.Issuer.CommonName,
		IssuerOrg:    cert.Issuer.Organization,
		SubjectDN:    cert.Subject.String(),
		SubjectCN:    cert.Subject.CommonName,
		SubjectOrg:   cert.Subject.Organization,
		FingerprintHash: clients.CertificateResponseFingerprintHash{
			MD5:    clients.MD5Fingerprint(cert.Raw),
			SHA1:   clients.SHA1Fingerprint(cert.Raw),
			SHA256: clients.SHA256Fingerprint(cert.Raw),
		},
	}
	if options.Cert {
		response.Certificate = clients.PemEncode(cert.Raw)
	}
	return response
}

// SupportedTLSVersions returns the list of ztls library supported tls versions
func (c *Client) SupportedTLSVersions() ([]string, error) {
	return SupportedTlsVersions, nil
}

// SupportedTLSCiphers returns the list of ztls library supported ciphers
func (c *Client) SupportedTLSCiphers() ([]string, error) {
	return AllCiphersNames, nil
}
