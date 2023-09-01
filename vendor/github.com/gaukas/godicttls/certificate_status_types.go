package godicttls

// source: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#certificate-status
// last updated: March 2023

const (
	CertStatusType_ocsp       uint8 = 1
	CertStatusType_ocsp_multi uint8 = 2
)

var DictCertificateStatusTypeValueIndexed = map[uint8]string{
	1: "ocsp",
	2: "ocsp_multi",
}

var DictCertificateStatusTypeNameIndexed = map[string]uint8{
	"ocsp":       1,
	"ocsp_multi": 2,
}
