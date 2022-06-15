package fastdialer

import (
	"crypto/tls"

	"github.com/ulule/deepcopier"
	ztls "github.com/zmap/zcrypto/tls"
	"golang.org/x/net/idna"
)

func AsTLSConfig(ztlsConfig *ztls.Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{}
	err := deepcopier.Copy(ztlsConfig).To(tlsConfig)
	return tlsConfig, err
}

func AsZTLSConfig(tlsConfig *tls.Config) (*ztls.Config, error) {
	ztlsConfig := &ztls.Config{}
	err := deepcopier.Copy(tlsConfig).To(ztlsConfig)
	return ztlsConfig, err
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
