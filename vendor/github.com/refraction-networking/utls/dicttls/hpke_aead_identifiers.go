package dicttls

// source: https://www.iana.org/assignments/hpke/hpke.xhtml
// last updated: December 2023

const (
	AEAD_AES_128_GCM       uint16 = 0x0001 // NIST Special Publication 800-38D
	AEAD_AES_256_GCM       uint16 = 0x0002 // NIST Special Publication 800-38D
	AEAD_CHACHA20_POLY1305 uint16 = 0x0003 // RFC 8439
	AEAD_EXPORT_ONLY       uint16 = 0xFFFF // RFC 9180
)

var DictAEADIdentifierValueIndexed = map[uint16]string{
	0x0000: "Reserved", // RFC 9180
	0x0001: "AES-128-GCM",
	0x0002: "AES-256-GCM",
	0x0003: "ChaCha20Poly1305",
	0xFFFF: "Export-only", // RFC 9180
}
