package dicttls

// source: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-2
// last updated: March 2023

const (
	ClientCertTypeIdentifier_rsa_sign         uint8 = 1
	ClientCertTypeIdentifier_dss_sign         uint8 = 2
	ClientCertTypeIdentifier_rsa_fixed_dh     uint8 = 3
	ClientCertTypeIdentifier_dss_fixed_dh     uint8 = 4
	ClientCertTypeIdentifier_rsa_ephemeral_dh uint8 = 5
	ClientCertTypeIdentifier_dss_ephemeral_dh uint8 = 6
	ClientCertTypeIdentifier_fortezza_dms     uint8 = 20
	ClientCertTypeIdentifier_ecdsa_sign       uint8 = 64
	ClientCertTypeIdentifier_rsa_fixed_ecdh   uint8 = 65
	ClientCertTypeIdentifier_ecdsa_fixed_ecdh uint8 = 66
	ClientCertTypeIdentifier_gost_sign256     uint8 = 67
	ClientCertTypeIdentifier_gost_sign512     uint8 = 68
)

var DictClientCertificateTypeIdentifierValueIndexed = map[uint8]string{
	1:  "rsa_sign",
	2:  "dss_sign",
	3:  "rsa_fixed_dh",
	4:  "dss_fixed_dh",
	5:  "rsa_ephemeral_dh",
	6:  "dss_ephemeral_dh",
	20: "fortezza_dms",
	64: "ecdsa_sign",
	65: "rsa_fixed_ecdh",
	66: "ecdsa_fixed_ecdh",
	67: "gost_sign256",
	68: "gost_sign512",
}

var DictClientCertificateTypeIdentifierNameIndexed = map[string]uint8{
	"rsa_sign":         1,
	"dss_sign":         2,
	"rsa_fixed_dh":     3,
	"dss_fixed_dh":     4,
	"rsa_ephemeral_dh": 5,
	"dss_ephemeral_dh": 6,
	"fortezza_dms":     20,
	"ecdsa_sign":       64,
	"rsa_fixed_ecdh":   65,
	"ecdsa_fixed_ecdh": 66,
	"gost_sign256":     67,
	"gost_sign512":     68,
}
