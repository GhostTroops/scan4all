package godicttls

// source: https://www.iana.org/assignments/tls-parameters/tls-signaturescheme.csv
// last updated: March 2023

const (
	SigScheme_rsa_pkcs1_sha1                    uint16 = 0x0201
	SigScheme_ecdsa_sha1                        uint16 = 0x0203
	SigScheme_rsa_pkcs1_sha256                  uint16 = 0x0401
	SigScheme_ecdsa_secp256r1_sha256            uint16 = 0x0403
	SigScheme_rsa_pkcs1_sha256_legacy           uint16 = 0x0420
	SigScheme_rsa_pkcs1_sha384                  uint16 = 0x0501
	SigScheme_ecdsa_secp384r1_sha384            uint16 = 0x0503
	SigScheme_rsa_pkcs1_sha384_legacy           uint16 = 0x0520
	SigScheme_rsa_pkcs1_sha512                  uint16 = 0x0601
	SigScheme_ecdsa_secp521r1_sha512            uint16 = 0x0603
	SigScheme_rsa_pkcs1_sha512_legacy           uint16 = 0x0620
	SigScheme_eccsi_sha256                      uint16 = 0x0704
	SigScheme_iso_ibs1                          uint16 = 0x0705
	SigScheme_iso_ibs2                          uint16 = 0x0706
	SigScheme_iso_chinese_ibs                   uint16 = 0x0707
	SigScheme_sm2sig_sm3                        uint16 = 0x0708
	SigScheme_gostr34102012_256a                uint16 = 0x0709
	SigScheme_gostr34102012_256b                uint16 = 0x070A
	SigScheme_gostr34102012_256c                uint16 = 0x070B
	SigScheme_gostr34102012_256d                uint16 = 0x070C
	SigScheme_gostr34102012_512a                uint16 = 0x070D
	SigScheme_gostr34102012_512b                uint16 = 0x070E
	SigScheme_gostr34102012_512c                uint16 = 0x070F
	SigScheme_rsa_pss_rsae_sha256               uint16 = 0x0804
	SigScheme_rsa_pss_rsae_sha384               uint16 = 0x0805
	SigScheme_rsa_pss_rsae_sha512               uint16 = 0x0806
	SigScheme_ed25519                           uint16 = 0x0807
	SigScheme_ed448                             uint16 = 0x0808
	SigScheme_rsa_pss_pss_sha256                uint16 = 0x0809
	SigScheme_rsa_pss_pss_sha384                uint16 = 0x080A
	SigScheme_rsa_pss_pss_sha512                uint16 = 0x080B
	SigScheme_ecdsa_brainpoolP256r1tls13_sha256 uint16 = 0x081A
	SigScheme_ecdsa_brainpoolP384r1tls13_sha384 uint16 = 0x081B
	SigScheme_ecdsa_brainpoolP512r1tls13_sha512 uint16 = 0x081C
)

var DictSignatureSchemeValueIndexed = map[uint16]string{
	0x0201: "rsa_pkcs1_sha1",
	0x0203: "ecdsa_sha1",
	0x0401: "rsa_pkcs1_sha256",
	0x0403: "ecdsa_secp256r1_sha256",
	0x0420: "rsa_pkcs1_sha256_legacy",
	0x0501: "rsa_pkcs1_sha384",
	0x0503: "ecdsa_secp384r1_sha384",
	0x0520: "rsa_pkcs1_sha384_legacy",
	0x0601: "rsa_pkcs1_sha512",
	0x0603: "ecdsa_secp521r1_sha512",
	0x0620: "rsa_pkcs1_sha512_legacy",
	0x0704: "eccsi_sha256",
	0x0705: "iso_ibs1",
	0x0706: "iso_ibs2",
	0x0707: "iso_chinese_ibs",
	0x0708: "sm2sig_sm3",
	0x0709: "gostr34102012_256a",
	0x070A: "gostr34102012_256b",
	0x070B: "gostr34102012_256c",
	0x070C: "gostr34102012_256d",
	0x070D: "gostr34102012_512a",
	0x070E: "gostr34102012_512b",
	0x070F: "gostr34102012_512c",
	0x0804: "rsa_pss_rsae_sha256",
	0x0805: "rsa_pss_rsae_sha384",
	0x0806: "rsa_pss_rsae_sha512",
	0x0807: "ed25519",
	0x0808: "ed448",
	0x0809: "rsa_pss_pss_sha256",
	0x080A: "rsa_pss_pss_sha384",
	0x080B: "rsa_pss_pss_sha512",
	0x081A: "ecdsa_brainpoolP256r1tls13_sha256",
	0x081B: "ecdsa_brainpoolP384r1tls13_sha384",
	0x081C: "ecdsa_brainpoolP512r1tls13_sha512",
}

var DictSignatureSchemeNameIndexed = map[string]uint16{
	"rsa_pkcs1_sha1":                      0x0201,
	"Reserved for backward compatibility": 0x0202,
	"ecdsa_sha1":                          0x0203,
	"rsa_pkcs1_sha256":                    0x0401,
	"ecdsa_secp256r1_sha256":              0x0403,
	"rsa_pkcs1_sha256_legacy":             0x0420,
	"rsa_pkcs1_sha384":                    0x0501,
	"ecdsa_secp384r1_sha384":              0x0503,
	"rsa_pkcs1_sha384_legacy":             0x0520,
	"rsa_pkcs1_sha512":                    0x0601,
	"ecdsa_secp521r1_sha512":              0x0603,
	"rsa_pkcs1_sha512_legacy":             0x0620,
	"eccsi_sha256":                        0x0704,
	"iso_ibs1":                            0x0705,
	"iso_ibs2":                            0x0706,
	"iso_chinese_ibs":                     0x0707,
	"sm2sig_sm3":                          0x0708,
	"gostr34102012_256a":                  0x0709,
	"gostr34102012_256b":                  0x070A,
	"gostr34102012_256c":                  0x070B,
	"gostr34102012_256d":                  0x070C,
	"gostr34102012_512a":                  0x070D,
	"gostr34102012_512b":                  0x070E,
	"gostr34102012_512c":                  0x070F,
	"rsa_pss_rsae_sha256":                 0x0804,
	"rsa_pss_rsae_sha384":                 0x0805,
	"rsa_pss_rsae_sha512":                 0x0806,
	"ed25519":                             0x0807,
	"ed448":                               0x0808,
	"rsa_pss_pss_sha256":                  0x0809,
	"rsa_pss_pss_sha384":                  0x080A,
	"rsa_pss_pss_sha512":                  0x080B,
	"ecdsa_brainpoolP256r1tls13_sha256":   0x081A,
	"ecdsa_brainpoolP384r1tls13_sha384":   0x081B,
	"ecdsa_brainpoolP512r1tls13_sha512":   0x081C,
}
