package godicttls

// source: https://www.iana.org/assignments/tls-parameters/tls-kdf-ids.csv
// last updated: March 2023

const (
	HKDF_SHA256 uint16 = 0x0001
	HKDF_SHA384 uint16 = 0x0002
)

var DictKDFIdentifierValueIndexed = map[uint16]string{
	0x0001: "HKDF_SHA256",
	0x0002: "HKDF_SHA384",
}

var DictKDFIdentifierNameIndexed = map[string]uint16{
	"HKDF_SHA256": 0x0001,
	"HKDF_SHA384": 0x0002,
}
