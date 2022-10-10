// Package auto implements an automatic fallback mechanism based tls
// client which uses both crypto/tls first and zcrypto/tls on tls errors.
package auto

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/tlsx/pkg/output/stats"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/openssl"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/tls"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/ztls"
	"go.uber.org/multierr"
)

// Client is a TLS grabbing client using auto fallback
type Client struct {
	tlsClient     *tls.Client
	ztlsClient    *ztls.Client
	opensslClient *openssl.Client
}

// New creates a new grabbing client using auto fallback
func New(options *clients.Options) (*Client, error) {
	tlsClient, tlsErr := tls.New(options)
	ztlsClient, ztlsErr := ztls.New(options)
	opensslClient, opensslErr := openssl.New(options)
	if tlsErr != nil && ztlsErr != nil && (opensslErr != nil && opensslErr != openssl.ErrNotSupported) {
		return nil, multierr.Combine(tlsErr, ztlsErr, opensslErr)
	}
	return &Client{tlsClient: tlsClient, ztlsClient: ztlsClient, opensslClient: opensslClient}, nil
}

// Connect connects to a host and grabs the response data
func (c *Client) ConnectWithOptions(hostname, ip, port string, options clients.ConnectOptions) (*clients.Response, error) {
	var response *clients.Response
	var err, ztlsErr, opensslErr error
	if c.tlsClient != nil {
		if response, err = c.tlsClient.ConnectWithOptions(hostname, ip, port, options); err == nil {
			response.TLSConnection = "ctls"
			stats.IncrementCryptoTLSConnections()
			return response, nil
		}
	}
	if c.ztlsClient != nil {
		if response, ztlsErr = c.ztlsClient.ConnectWithOptions(hostname, ip, port, options); ztlsErr == nil {
			response.TLSConnection = "ztls"
			stats.IncrementZcryptoTLSConnections()
			return response, nil
		}
	}
	if c.opensslClient != nil {
		if response, opensslErr = c.opensslClient.ConnectWithOptions(hostname, ip, port, options); opensslErr == nil {
			response.TLSConnection = "openssl"
			stats.IncrementOpensslTLSConnections()
			return response, nil
		}
		if errors.Is(opensslErr, openssl.ErrNotSupported) {
			opensslErr = nil
		}
	}
	return nil, multierr.Combine(err, ztlsErr, opensslErr)
}

// SupportedTLSVersions returns the list of supported tls versions by all engines
func (c *Client) SupportedTLSVersions() ([]string, error) {
	return supportedTlsVersions, nil
}

// SupportedTLSCiphers returns the list of supported ciphers by all engines
func (c *Client) SupportedTLSCiphers() ([]string, error) {
	return allCiphersNames, nil
}
