package fastdialer

import (
	"crypto/tls"

	ztls "github.com/zmap/zcrypto/tls"
	"golang.org/x/net/idna"
)

func AsTLSConfig(ztlsConfig *ztls.Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		Certificates:           asTLSCertificates(ztlsConfig.Certificates),
		NextProtos:             ztlsConfig.NextProtos,
		ServerName:             ztlsConfig.ServerName,
		ClientAuth:             tls.ClientAuthType(ztlsConfig.ClientAuth),
		InsecureSkipVerify:     ztlsConfig.InsecureSkipVerify,
		CipherSuites:           ztlsConfig.CipherSuites,
		SessionTicketsDisabled: ztlsConfig.SessionTicketsDisabled,
		MinVersion:             ztlsConfig.MinVersion,
		MaxVersion:             ztlsConfig.MaxVersion,
	}
	return tlsConfig, nil
}

func AsZTLSConfig(tlsConfig *tls.Config) (*ztls.Config, error) {
	ztlsConfig := &ztls.Config{
		Certificates:           asZTLSCertificates(tlsConfig.Certificates),
		NextProtos:             tlsConfig.NextProtos,
		ServerName:             tlsConfig.ServerName,
		ClientAuth:             ztls.ClientAuthType(tlsConfig.ClientAuth),
		InsecureSkipVerify:     tlsConfig.InsecureSkipVerify,
		CipherSuites:           tlsConfig.CipherSuites,
		SessionTicketsDisabled: tlsConfig.SessionTicketsDisabled,
		MinVersion:             tlsConfig.MinVersion,
		MaxVersion:             tlsConfig.MaxVersion,
	}
	return ztlsConfig, nil
}

// asTLSCertificates converts certs for crypto/tls. It leaves Leaf unset because
// zcrypto has its own x509 type, and crypto/tls parses the leaf from the chain
// when Leaf is nil.
func asTLSCertificates(zcerts []ztls.Certificate) []tls.Certificate {
	if zcerts == nil {
		return nil
	}
	certs := make([]tls.Certificate, len(zcerts))
	for i, zcert := range zcerts {
		certs[i] = tls.Certificate{
			Certificate:                  zcert.Certificate,
			PrivateKey:                   zcert.PrivateKey,
			SupportedSignatureAlgorithms: convertSlice[tls.SignatureScheme](zcert.SupportedSignatureAlgorithms),
			OCSPStaple:                   zcert.OCSPStaple,
			SignedCertificateTimestamps:  zcert.SignedCertificateTimestamps,
		}
	}
	return certs
}

// asZTLSCertificates converts certs for ztls. It leaves Leaf unset because
// zcrypto has its own x509 type, and it parses the leaf from the chain when
// Leaf is nil.
func asZTLSCertificates(certs []tls.Certificate) []ztls.Certificate {
	if certs == nil {
		return nil
	}
	zcerts := make([]ztls.Certificate, len(certs))
	for i, cert := range certs {
		zcerts[i] = ztls.Certificate{
			Certificate:                  cert.Certificate,
			PrivateKey:                   cert.PrivateKey,
			SupportedSignatureAlgorithms: convertSlice[ztls.SignatureScheme](cert.SupportedSignatureAlgorithms),
			OCSPStaple:                   cert.OCSPStaple,
			SignedCertificateTimestamps:  cert.SignedCertificateTimestamps,
		}
	}
	return zcerts
}

// convertSlice converts protocol code points, such as curve IDs, between
// their crypto/tls, utls and zcrypto types.
func convertSlice[To, From ~uint16](s []From) []To {
	if s == nil {
		return nil
	}
	out := make([]To, len(s))
	for i, v := range s {
		out[i] = To(v)
	}
	return out
}

func IsTLS13(config interface{}) bool {
	switch c := config.(type) {
	case *tls.Config:
		return c.MinVersion == tls.VersionTLS13
	case *ztls.Config:
		return c.MinVersion == tls.VersionTLS13
	}

	return false
}

func asAscii(hostname string) string {
	hostnameAscii, _ := idna.ToASCII(hostname)
	return hostnameAscii
}
