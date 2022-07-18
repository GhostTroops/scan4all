package acme

import (
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"go.uber.org/zap"
)

// CleanupStorage perform cleanup routines tasks
func CleanupStorage() {
	cleanupOptions := certmagic.CleanStorageOptions{OCSPStaples: true}
	certmagic.CleanStorage(context.Background(), certmagic.Default.Storage, cleanupOptions)
}

// HandleWildcardCertificates handles ACME wildcard cert generation with DNS
// challenge using certmagic library from caddyserver.
func HandleWildcardCertificates(domain, email string, store *Provider, debug bool) ([]tls.Certificate, error) {
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, err
	}
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = email
	certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
		DNSProvider: store,
		Resolvers: []string{
			"8.8.8.8:53",
			"8.8.4.4:53",
			"1.1.1.1:53",
			"1.0.0.1:53",
		},
	}
	originalDomain := strings.TrimPrefix(domain, "*.")

	certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
	if debug {
		certmagic.DefaultACME.Logger = logger
	}
	certmagic.DefaultACME.DisableHTTPChallenge = true
	certmagic.DefaultACME.DisableTLSALPNChallenge = true

	cfg := certmagic.NewDefault()
	if debug {
		cfg.Logger = logger
	}

	var creating bool
	if !certAlreadyExists(cfg, &certmagic.DefaultACME, domain) {
		creating = true
		gologger.Info().Msgf("Requesting SSL Certificate for:  [%s, %s]", domain, strings.TrimPrefix(domain, "*."))
	} else {
		gologger.Info().Msgf("Loading existing SSL Certificate for:  [%s, %s]", domain, strings.TrimPrefix(domain, "*."))
	}

	// this obtains certificates or renews them if necessary
	if syncerr := cfg.ObtainCertSync(context.Background(), domain); syncerr != nil {
		return nil, syncerr
	}
	domains := []string{domain, originalDomain}
	go func() {
		syncerr := cfg.ManageAsync(context.Background(), domains)
		if syncerr != nil {
			gologger.Error().Msgf("Could not manageasync certmagic certs: %s", err)
		}
	}()

	if creating {
		home, _ := os.UserHomeDir()
		gologger.Info().Msgf("Successfully Created SSL Certificate at: %s", filepath.Join(home, ".local", "share", "certmagic"))
	}

	// attempts to extract certificates from caddy
	var certs []tls.Certificate
	for _, domain := range domains {
		var retried bool
	retry_cert:
		certPath, privKeyPath, err := extractCaddyPaths(cfg, &certmagic.DefaultACME, domain)
		if err != nil {
			return nil, err
		}
		cert, err := tls.LoadX509KeyPair(certPath, privKeyPath)
		if err != nil && !retried {
			retried = true
			// wait I/O to sync
			time.Sleep(5 * time.Second)
			goto retry_cert
		}
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// certAlreadyExists returns true if a cert already exists
func certAlreadyExists(cfg *certmagic.Config, issuer certmagic.Issuer, domain string) bool {
	issuerKey := issuer.IssuerKey()
	certKey := certmagic.StorageKeys.SiteCert(issuerKey, domain)
	keyKey := certmagic.StorageKeys.SitePrivateKey(issuerKey, domain)
	metaKey := certmagic.StorageKeys.SiteMeta(issuerKey, domain)
	return cfg.Storage.Exists(context.Background(), certKey) &&
		cfg.Storage.Exists(context.Background(), keyKey) &&
		cfg.Storage.Exists(context.Background(), metaKey)
}

// extractCaddyPaths attempts to extract cert and private key through the layers of abstractions from the domain name
func extractCaddyPaths(cfg *certmagic.Config, issuer certmagic.Issuer, domain string) (certPath, privKeyPath string, err error) {
	issuerKey := issuer.IssuerKey()
	certId := certmagic.StorageKeys.SiteCert(issuerKey, domain)
	keyId := certmagic.StorageKeys.SitePrivateKey(issuerKey, domain)
	// we need to coerce the storage to file system one to be able to obtain access to the typed methods
	if cfgStorage, ok := cfg.Storage.(*certmagic.FileStorage); ok {
		certPath = cfgStorage.Filename(certId)
		privKeyPath = cfgStorage.Filename(keyId)
	}
	if certPath != "" && privKeyPath != "" {
		return
	}
	err = errors.New("couldn't extract cert and private key paths")
	return
}

// BuildTlsConfig with certificates
func BuildTlsConfigWithCertAndKeyPaths(certPath, privKeyPath, domain string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, privKeyPath)
	if err != nil {
		return nil, errors.New("Could not load certs and private key")
	}
	return BuildTlsConfigWithCerts(domain, cert)
}

// BuildTlsConfigWithExistingConfig with existing certificates
func BuildTlsConfigWithCerts(domain string, certs ...tls.Certificate) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       certs,
	}
	if domain != "" {
		tlsConfig.ServerName = domain
	}
	tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	return tlsConfig, nil
}
