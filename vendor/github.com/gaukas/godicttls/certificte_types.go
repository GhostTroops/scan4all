package godicttls

// source: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-3
// last updated: March 2023

const (
	CertType_X509           uint8 = 0
	CertType_OpenPGP        uint8 = 1
	CertType_Raw_Public_Key uint8 = 2
	CertType_1609Dot2       uint8 = 3
)

var DictCertificateTypeValueIndexed = map[uint8]string{
	0: "X509",
	1: "OpenPGP",
	2: "Raw Public Key",
	3: "1609Dot2",
}

var DictCertificateTypeNameIndexed = map[string]uint8{
	"X509":           0,
	"OpenPGP":        1,
	"Raw Public Key": 2,
	"1609Dot2":       3,
}
