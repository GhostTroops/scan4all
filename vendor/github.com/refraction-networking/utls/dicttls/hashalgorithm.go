package dicttls

// source: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
// last updated: March 2023

const (
	HashAlg_none      uint8 = 0 // deprecated in TLS 1.3
	HashAlg_md5       uint8 = 1 // deprecated in TLS 1.3
	HashAlg_sha1      uint8 = 2
	HashAlg_sha224    uint8 = 3 // deprecated in TLS 1.3
	HashAlg_sha256    uint8 = 4
	HashAlg_sha384    uint8 = 5
	HashAlg_sha512    uint8 = 6
	HashAlg_Intrinsic uint8 = 8
)

var DictHashAlgorithmValueIndexed = map[uint8]string{
	0: "none",
	1: "md5",
	2: "sha1",
	3: "sha224",
	4: "sha256",
	5: "sha384",
	6: "sha512",
	7: "Reserved",
	8: "Intrinsic",
}

var DictHashAlgorithmNameIndexed = map[string]uint8{
	"none":      0,
	"md5":       1,
	"sha1":      2,
	"sha224":    3,
	"sha256":    4,
	"sha384":    5,
	"sha512":    6,
	"Reserved":  7,
	"Intrinsic": 8,
}
