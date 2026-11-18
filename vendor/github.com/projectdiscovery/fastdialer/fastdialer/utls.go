package fastdialer

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	utls "github.com/refraction-networking/utls"
)

// asUTLSConfig converts cfg for an impersonated dial. It keeps every client
// field of cfg, adapting the ones whose types differ in utls, and leaves the
// server-only fields unset, as well as Rand, which Go 1.27 deprecates.
func asUTLSConfig(cfg *tls.Config) *utls.Config {
	ucfg := &utls.Config{
		Time:                           cfg.Time,
		Certificates:                   asUTLSCertificates(cfg.Certificates),
		VerifyPeerCertificate:          cfg.VerifyPeerCertificate,
		VerifyConnection:               asUTLSConnectionStateFunc(cfg.VerifyConnection),
		RootCAs:                        cfg.RootCAs,
		NextProtos:                     cfg.NextProtos,
		ServerName:                     cfg.ServerName,
		InsecureSkipVerify:             cfg.InsecureSkipVerify,
		CipherSuites:                   cfg.CipherSuites,
		SessionTicketsDisabled:         cfg.SessionTicketsDisabled,
		MinVersion:                     cfg.MinVersion,
		MaxVersion:                     cfg.MaxVersion,
		CurvePreferences:               convertSlice[utls.CurveID](cfg.CurvePreferences),
		DynamicRecordSizingDisabled:    cfg.DynamicRecordSizingDisabled,
		Renegotiation:                  utls.RenegotiationSupport(cfg.Renegotiation),
		KeyLogWriter:                   cfg.KeyLogWriter,
		EncryptedClientHelloConfigList: cfg.EncryptedClientHelloConfigList,

		EncryptedClientHelloRejectionVerify: asUTLSConnectionStateFunc(cfg.EncryptedClientHelloRejectionVerify),

		// Skip resumption when the ClientHello lacks the extension that
		// carries the session, instead of panicking as utls does for custom
		// ClientHellos.
		PreferSkipResumptionOnNilExtension: true,
		// Omit the pre_shared_key extension when there is no session to
		// resume, as browsers do, instead of failing the handshake.
		OmitEmptyPsk: true,
	}
	if cfg.ClientSessionCache != nil {
		ucfg.ClientSessionCache = utlsSessionCache{cfg.ClientSessionCache}
		if !cfg.InsecureSkipVerify {
			ucfg.VerifyConnection = verifyResumedChains(cfg, ucfg.VerifyConnection)
		}
	}
	if cfg.MinVersion != 0 || cfg.MaxVersion != 0 {
		ucfg.VerifyConnection = verifyVersion(cfg.MinVersion, cfg.MaxVersion, ucfg.VerifyConnection)
	}
	if getCert := cfg.GetClientCertificate; getCert != nil {
		ucfg.GetClientCertificate = func(cri *utls.CertificateRequestInfo) (*utls.Certificate, error) {
			// utls keeps the handshake context unexported, so the
			// Context method of the request returns nil
			cert, err := getCert(&tls.CertificateRequestInfo{
				AcceptableCAs:    cri.AcceptableCAs,
				SignatureSchemes: convertSlice[tls.SignatureScheme](cri.SignatureSchemes),
				Version:          cri.Version,
			})
			if err != nil {
				return nil, err
			}
			ucert := asUTLSCertificate(cert)
			return &ucert, nil
		}
	}

	return ucfg
}

func asUTLSCertificates(certs []tls.Certificate) []utls.Certificate {
	if certs == nil {
		return nil
	}
	ucerts := make([]utls.Certificate, len(certs))
	for i := range certs {
		ucerts[i] = asUTLSCertificate(&certs[i])
	}
	return ucerts
}

func asUTLSCertificate(cert *tls.Certificate) utls.Certificate {
	return utls.Certificate{
		Certificate:                  cert.Certificate,
		PrivateKey:                   cert.PrivateKey,
		SupportedSignatureAlgorithms: convertSlice[utls.SignatureScheme](cert.SupportedSignatureAlgorithms),
		OCSPStaple:                   cert.OCSPStaple,
		SignedCertificateTimestamps:  cert.SignedCertificateTimestamps,
		Leaf:                         cert.Leaf,
	}
}

// asUTLSConnectionStateFunc adapts a connection callback for utls. The state
// passed to f has no keying material, so its ExportKeyingMaterial panics;
// crypto/tls has none during the handshake either. The state also leaves unset
// the fields that utls doesn't expose, such as CurveID and HelloRetryRequest.
func asUTLSConnectionStateFunc(f func(tls.ConnectionState) error) func(utls.ConnectionState) error {
	if f == nil {
		return nil
	}
	return func(cs utls.ConnectionState) error {
		return f(tls.ConnectionState{
			Version:                     cs.Version,
			HandshakeComplete:           cs.HandshakeComplete,
			DidResume:                   cs.DidResume,
			CipherSuite:                 cs.CipherSuite,
			NegotiatedProtocol:          cs.NegotiatedProtocol,
			ServerName:                  cs.ServerName,
			PeerCertificates:            cs.PeerCertificates,
			VerifiedChains:              cs.VerifiedChains,
			SignedCertificateTimestamps: cs.SignedCertificateTimestamps,
			OCSPResponse:                cs.OCSPResponse,
			TLSUnique:                   cs.TLSUnique,
			ECHAccepted:                 cs.ECHAccepted,
		})
	}
}

// verifyVersion fails a connection whose version is below minVersion or above
// maxVersion, where zero leaves that end open. utls replaces MinVersion and
// MaxVersion with the versions of the ClientHello spec, so it doesn't apply
// those of the config.
func verifyVersion(minVersion, maxVersion uint16, next func(utls.ConnectionState) error) func(utls.ConnectionState) error {
	return func(cs utls.ConnectionState) error {
		if cs.Version < minVersion || (maxVersion != 0 && cs.Version > maxVersion) {
			return fmt.Errorf("tls: server selected %s, outside MinVersion and MaxVersion", tls.VersionName(cs.Version))
		}
		if next == nil {
			return nil
		}
		return next(cs)
	}
}

var errUntrustedSession = errors.New("tls: the certificate of the resumed session is no longer trusted")

// verifyResumedChains fails a resumed connection unless a chain verified for
// its session is still valid and leads to a root that cfg trusts. crypto/tls
// checks this before it resumes a session, but utls v1.8.2 doesn't. The
// failed handshake evicts the session, so the next dial makes a full one.
func verifyResumedChains(cfg *tls.Config, next func(utls.ConnectionState) error) func(utls.ConnectionState) error {
	return func(cs utls.ConnectionState) error {
		if cs.DidResume && !anyValidVerifiedChain(cs.VerifiedChains, cfg) {
			return errUntrustedSession
		}
		if next == nil {
			return nil
		}
		return next(cs)
	}
}

// anyValidVerifiedChain reports whether one of chains is within its validity
// period and leads to a root in cfg.RootCAs, or in the system roots if that is
// nil. Unlike crypto/tls on Linux, it verifies a chain from its leaf rather
// than its root, which works with the system roots of every platform
// (go.dev/issue/77376).
func anyValidVerifiedChain(chains [][]*x509.Certificate, cfg *tls.Config) bool {
	now := time.Now()
	if cfg.Time != nil {
		now = cfg.Time()
	}
	opts := x509.VerifyOptions{
		CurrentTime: now,
		Roots:       cfg.RootCAs,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		if slices.ContainsFunc(chain, func(cert *x509.Certificate) bool {
			return now.Before(cert.NotBefore) || now.After(cert.NotAfter)
		}) {
			continue
		}
		opts.Intermediates = x509.NewCertPool()
		for _, cert := range chain[1:max(1, len(chain)-1)] {
			opts.Intermediates.AddCert(cert)
		}
		if _, err := chain[0].Verify(opts); err == nil {
			return true
		}
	}
	return false
}

// utlsSessionCache keeps utls sessions in a crypto/tls session cache by
// converting them through their serialized form. A session that doesn't
// convert is a cache miss, and only TLS 1.3 sessions do: utls v1.8.2 lacks
// the curve that crypto/tls has recorded in TLS 1.2 sessions since Go 1.25.
type utlsSessionCache struct {
	cache tls.ClientSessionCache
}

func (c utlsSessionCache) Get(sessionKey string) (*utls.ClientSessionState, bool) {
	cs, ok := c.cache.Get(sessionKey)
	if !ok {
		return nil, false
	}
	ticket, state, err := cs.ResumptionState()
	if err != nil || state == nil {
		return nil, false
	}
	b, err := state.Bytes()
	if err != nil {
		return nil, false
	}
	ustate, err := utls.ParseSessionState(b)
	if err != nil {
		return nil, false
	}
	ucs, err := utls.NewResumptionState(ticket, ustate)
	return ucs, err == nil
}

func (c utlsSessionCache) Put(sessionKey string, ucs *utls.ClientSessionState) {
	ticket, ustate, err := ucs.ResumptionState()
	if err != nil {
		return
	}
	// utls evicts a session by putting nil
	if ustate == nil {
		c.cache.Put(sessionKey, nil)
		return
	}
	b, err := ustate.Bytes()
	if err != nil {
		return
	}
	state, err := tls.ParseSessionState(b)
	if err != nil {
		return
	}
	cs, err := tls.NewResumptionState(ticket, state)
	if err != nil {
		return
	}
	c.cache.Put(sessionKey, cs)
}
