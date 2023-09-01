package godicttls

// source: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
// last updated: March 2023

const (
	SupportedGroups_sect163k1                       uint16 = 1
	SupportedGroups_sect163r1                       uint16 = 2
	SupportedGroups_sect163r2                       uint16 = 3
	SupportedGroups_sect193r1                       uint16 = 4
	SupportedGroups_sect193r2                       uint16 = 5
	SupportedGroups_sect233k1                       uint16 = 6
	SupportedGroups_sect233r1                       uint16 = 7
	SupportedGroups_sect239k1                       uint16 = 8
	SupportedGroups_sect283k1                       uint16 = 9
	SupportedGroups_sect283r1                       uint16 = 10
	SupportedGroups_sect409k1                       uint16 = 11
	SupportedGroups_sect409r1                       uint16 = 12
	SupportedGroups_sect571k1                       uint16 = 13
	SupportedGroups_sect571r1                       uint16 = 14
	SupportedGroups_secp160k1                       uint16 = 15
	SupportedGroups_secp160r1                       uint16 = 16
	SupportedGroups_secp160r2                       uint16 = 17
	SupportedGroups_secp192k1                       uint16 = 18
	SupportedGroups_secp192r1                       uint16 = 19
	SupportedGroups_secp224k1                       uint16 = 20
	SupportedGroups_secp224r1                       uint16 = 21
	SupportedGroups_secp256k1                       uint16 = 22
	SupportedGroups_secp256r1                       uint16 = 23
	SupportedGroups_secp384r1                       uint16 = 24
	SupportedGroups_secp521r1                       uint16 = 25
	SupportedGroups_brainpoolP256r1                 uint16 = 26
	SupportedGroups_brainpoolP384r1                 uint16 = 27
	SupportedGroups_brainpoolP512r1                 uint16 = 28
	SupportedGroups_x25519                          uint16 = 29
	SupportedGroups_x448                            uint16 = 30
	SupportedGroups_brainpoolP256r1tls13            uint16 = 31
	SupportedGroups_brainpoolP384r1tls13            uint16 = 32
	SupportedGroups_brainpoolP512r1tls13            uint16 = 33
	SupportedGroups_GC256A                          uint16 = 34
	SupportedGroups_GC256B                          uint16 = 35
	SupportedGroups_GC256C                          uint16 = 36
	SupportedGroups_GC256D                          uint16 = 37
	SupportedGroups_GC512A                          uint16 = 38
	SupportedGroups_GC512B                          uint16 = 39
	SupportedGroups_GC512C                          uint16 = 40
	SupportedGroups_curveSM2                        uint16 = 41
	SupportedGroups_ffdhe2048                       uint16 = 256
	SupportedGroups_ffdhe3072                       uint16 = 257
	SupportedGroups_ffdhe4096                       uint16 = 258
	SupportedGroups_ffdhe6144                       uint16 = 259
	SupportedGroups_ffdhe8192                       uint16 = 260
	SupportedGroups_arbitrary_explicit_prime_curves uint16 = 65281
	SupportedGroups_arbitrary_explicit_char2_curves uint16 = 65282
)

var DictSupportedGroupsValueIndexed = map[uint16]string{
	1:     "sect163k1",
	2:     "sect163r1",
	3:     "sect163r2",
	4:     "sect193r1",
	5:     "sect193r2",
	6:     "sect233k1",
	7:     "sect233r1",
	8:     "sect239k1",
	9:     "sect283k1",
	10:    "sect283r1",
	11:    "sect409k1",
	12:    "sect409r1",
	13:    "sect571k1",
	14:    "sect571r1",
	15:    "secp160k1",
	16:    "secp160r1",
	17:    "secp160r2",
	18:    "secp192k1",
	19:    "secp192r1",
	20:    "secp224k1",
	21:    "secp224r1",
	22:    "secp256k1",
	23:    "secp256r1",
	24:    "secp384r1",
	25:    "secp521r1",
	26:    "brainpoolP256r1",
	27:    "brainpoolP384r1",
	28:    "brainpoolP512r1",
	29:    "x25519",
	30:    "x448",
	31:    "brainpoolP256r1tls13",
	32:    "brainpoolP384r1tls13",
	33:    "brainpoolP512r1tls13",
	34:    "GC256A",
	35:    "GC256B",
	36:    "GC256C",
	37:    "GC256D",
	38:    "GC512A",
	39:    "GC512B",
	40:    "GC512C",
	41:    "curveSM2",
	256:   "ffdhe2048",
	257:   "ffdhe3072",
	258:   "ffdhe4096",
	259:   "ffdhe6144",
	260:   "ffdhe8192",
	65281: "arbitrary_explicit_prime_curves",
	65282: "arbitrary_explicit_char2_curves",
}

var DictSupportedGroupsNameIndexed = map[string]uint16{
	"sect163k1":                       1,
	"sect163r1":                       2,
	"sect163r2":                       3,
	"sect193r1":                       4,
	"sect193r2":                       5,
	"sect233k1":                       6,
	"sect233r1":                       7,
	"sect239k1":                       8,
	"sect283k1":                       9,
	"sect283r1":                       10,
	"sect409k1":                       11,
	"sect409r1":                       12,
	"sect571k1":                       13,
	"sect571r1":                       14,
	"secp160k1":                       15,
	"secp160r1":                       16,
	"secp160r2":                       17,
	"secp192k1":                       18,
	"secp192r1":                       19,
	"secp224k1":                       20,
	"secp224r1":                       21,
	"secp256k1":                       22,
	"secp256r1":                       23,
	"secp384r1":                       24,
	"secp521r1":                       25,
	"brainpoolP256r1":                 26,
	"brainpoolP384r1":                 27,
	"brainpoolP512r1":                 28,
	"x25519":                          29,
	"x448":                            30,
	"brainpoolP256r1tls13":            31,
	"brainpoolP384r1tls13":            32,
	"brainpoolP512r1tls13":            33,
	"GC256A":                          34,
	"GC256B":                          35,
	"GC256C":                          36,
	"GC256D":                          37,
	"GC512A":                          38,
	"GC512B":                          39,
	"GC512C":                          40,
	"curveSM2":                        41,
	"ffdhe2048":                       256,
	"ffdhe3072":                       257,
	"ffdhe4096":                       258,
	"ffdhe6144":                       259,
	"ffdhe8192":                       260,
	"arbitrary_explicit_prime_curves": 65281,
	"arbitrary_explicit_char2_curves": 65282,
}
