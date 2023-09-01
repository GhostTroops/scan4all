package godicttls

// Note: values in this file was used in TLS 1.2's signature_algorithms extension
// in combination with the values in hashalgorithm.go.
// signature_algorithms extension in TLS 1.3 uses values in signaturescheme.go

// source: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-16
// last updated: March 2023

const (
	SigAlg_anonymous         uint8 = 0 // deprecated in TLS 1.3
	SigAlg_rsa               uint8 = 1
	SigAlg_dsa               uint8 = 2 // deprecated in TLS 1.3
	SigAlg_ecdsa             uint8 = 3
	SigAlg_ed25519           uint8 = 7
	SigAlg_ed448             uint8 = 8
	SigAlg_gostr34102012_256 uint8 = 64 // value changed in TLS 1.3, to 0x0709-0x070C
	SigAlg_gostr34102012_512 uint8 = 65 // value changed in TLS 1.3, to 0x070D-0x070F
)

var DictSignatureAlgorithmValueIndexed = map[uint8]string{
	0:  "anonymous",
	1:  "rsa",
	2:  "dsa",
	3:  "ecdsa",
	7:  "ed25519",
	8:  "ed448",
	64: "gostr34102012_256",
	65: "gostr34102012_512",
}

var DictSignatureAlgorithmNameIndexed = map[string]uint8{
	"anonymous":         0,
	"rsa":               1,
	"dsa":               2,
	"ecdsa":             3,
	"ed25519":           7,
	"ed448":             8,
	"gostr34102012_256": 64,
	"gostr34102012_512": 65,
}
