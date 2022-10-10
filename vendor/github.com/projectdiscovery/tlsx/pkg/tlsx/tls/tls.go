// Package tls implements a tls grabbing implementation using
// standard package crypto/tls library.
package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/rs/xid"
)

// Client is a TLS grabbing client using crypto/tls
type Client struct {
	dialer    *fastdialer.Dialer
	tlsConfig *tls.Config
	options   *clients.Options
}

// versionStringToTLSVersion converts tls version string to version
var versionStringToTLSVersion = map[string]uint16{
	"tls10": tls.VersionTLS10,
	"tls11": tls.VersionTLS11,
	"tls12": tls.VersionTLS12,
	"tls13": tls.VersionTLS13,
}

// versionToTLSVersionString converts tls version to version string
var versionToTLSVersionString = map[uint16]string{
	tls.VersionTLS10: "tls10",
	tls.VersionTLS11: "tls11",
	tls.VersionTLS12: "tls12",
	tls.VersionTLS13: "tls13",
}

// New creates a new grabbing client using crypto/tls
func New(options *clients.Options) (*Client, error) {
	c := &Client{
		dialer: options.Fastdialer,
		tlsConfig: &tls.Config{
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
			InsecureSkipVerify: !options.VerifyServerCertificate,
		},
		options: options,
	}

	if options.AllCiphers {
		c.tlsConfig.CipherSuites = AllCiphers
	}
	if len(options.Ciphers) > 0 {
		if customCiphers, err := toTLSCiphers(options.Ciphers); err != nil {
			return nil, errors.Wrap(err, "could not get tls ciphers")
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

// Connect connects to a host and grabs the response data
func (c *Client) ConnectWithOptions(hostname, ip, port string, options clients.ConnectOptions) (*clients.Response, error) {
	address := net.JoinHostPort(hostname, port)

	if c.options.ScanAllIPs || len(c.options.IPVersion) > 0 {
		address = net.JoinHostPort(ip, port)
	}

	ctx := context.Background()
	if c.options.Timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(c.options.Timeout)*time.Second)
		defer cancel()
	}

	rawConn, err := c.dialer.Dial(ctx, "tcp", address)
	if err != nil {
		return nil, errors.Wrap(err, "could not dial address")
	}
	if rawConn == nil {
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
		customCiphers, err := toTLSCiphers(options.Ciphers)
		if err != nil {
			return nil, errors.Wrap(err, "could not get tls ciphers")
		}
		c.tlsConfig.CipherSuites = customCiphers
	}

	conn := tls.Client(rawConn, config)
	if err := conn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, errors.Wrap(err, "could not do handshake")
	}
	defer conn.Close()

	connectionState := conn.ConnectionState()
	if len(connectionState.PeerCertificates) == 0 {
		return nil, errors.New("no certificates returned by server")
	}
	tlsVersion := versionToTLSVersionString[connectionState.Version]
	tlsCipher := tls.CipherSuiteName(connectionState.CipherSuite)

	leafCertificate := connectionState.PeerCertificates[0]
	certificateChain := connectionState.PeerCertificates[1:]

	now := time.Now()
	response := &clients.Response{
		Timestamp:           &now,
		Host:                hostname,
		IP:                  resolvedIP,
		ProbeStatus:         true,
		Port:                port,
		Version:             tlsVersion,
		Cipher:              tlsCipher,
		TLSConnection:       "ctls",
		CertificateResponse: c.convertCertificateToResponse(hostname, leafCertificate),
		ServerName:          config.ServerName,
	}
	if c.options.TLSChain {
		for _, cert := range certificateChain {
			response.Chain = append(response.Chain, c.convertCertificateToResponse(hostname, cert))
		}
	}
	return response, nil
}

func (c *Client) convertCertificateToResponse(hostname string, cert *x509.Certificate) *clients.CertificateResponse {
	response := &clients.CertificateResponse{
		SubjectAN:    cert.DNSNames,
		Emails:       cert.EmailAddresses,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Expired:      clients.IsExpired(cert.NotAfter),
		SelfSigned:   clients.IsSelfSigned(cert.AuthorityKeyId, cert.SubjectKeyId),
		MisMatched:   clients.IsMisMatchedCert(hostname, append(cert.DNSNames, cert.Subject.CommonName)),
		WildCardCert: clients.IsWildCardCert(append(cert.DNSNames, cert.Subject.CommonName)),
		IssuerCN:     cert.Issuer.CommonName,
		IssuerOrg:    cert.Issuer.Organization,
		SubjectCN:    cert.Subject.CommonName,
		SubjectOrg:   cert.Subject.Organization,
		FingerprintHash: clients.CertificateResponseFingerprintHash{
			MD5:    clients.MD5Fingerprint(cert.Raw),
			SHA1:   clients.SHA1Fingerprint(cert.Raw),
			SHA256: clients.SHA256Fingerprint(cert.Raw),
		},
	}
	response.IssuerDN = clients.ParseASN1DNSequenceWithZpkixOrDefault(cert.RawIssuer, cert.Issuer.String())
	response.SubjectDN = clients.ParseASN1DNSequenceWithZpkixOrDefault(cert.RawSubject, cert.Subject.String())
	if c.options.Cert {
		response.Certificate = clients.PemEncode(cert.Raw)
	}
	return response
}

// SupportedTLSVersions returns the list of standard tls library supported tls versions
func (c *Client) SupportedTLSVersions() ([]string, error) {
	return SupportedTlsVersions, nil
}

// SupportedTLSCiphers returns the list of standard tls library supported ciphers
func (c *Client) SupportedTLSCiphers() ([]string, error) {
	return AllCiphersNames, nil
}
