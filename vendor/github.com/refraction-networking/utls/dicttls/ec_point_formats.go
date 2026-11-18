package dicttls

// source: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-9
// last updated: March 2023

const (
	ECPoint_uncompressed              uint8 = 0
	ECPoint_ansiX962_compressed_prime uint8 = 1
	ECPoint_ansiX962_compressed_char2 uint8 = 2
)

var DictECPointFormatValueIndexed = map[uint8]string{
	0: "uncompressed",
	1: "ansiX962_compressed_prime",
	2: "ansiX962_compressed_char2",
}

var DictECPointFormatNameIndexed = map[string]uint8{
	"uncompressed":              0,
	"ansiX962_compressed_prime": 1,
	"ansiX962_compressed_char2": 2,
}
