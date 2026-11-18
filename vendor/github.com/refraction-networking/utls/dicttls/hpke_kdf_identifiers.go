package dicttls

// source: https://www.iana.org/assignments/hpke/hpke.xhtml
// last updated: December 2023

const (
	HKDF_SHA256 uint16 = 0x0001
	HKDF_SHA384 uint16 = 0x0002
	HKDF_SHA512 uint16 = 0x0003
)

var DictKDFIdentifierValueIndexed = map[uint16]string{
	0x0000: "Reserved", // RFC 9180
	0x0001: "HKDF_SHA256",
	0x0002: "HKDF_SHA384",
	0x0003: "HKDF_SHA512",
}

var DictKDFIdentifierNameIndexed = map[string]uint16{
	"Reserved":    0x0000, // RFC 9180
	"HKDF_SHA256": 0x0001,
	"HKDF_SHA384": 0x0002,
	"HKDF_SHA512": 0x0003,
}
