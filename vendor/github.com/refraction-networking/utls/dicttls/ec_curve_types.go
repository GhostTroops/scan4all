package dicttls

// source: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-10
// last updated: March 2023

const (
	ECCurve_explicit_prime uint16 = 1
	ECCurve_explicit_char2 uint16 = 2
	ECCurve_named_curve    uint16 = 3
)

var DictECCurveTypeValueIndexed = map[uint16]string{
	1: "explicit_prime",
	2: "explicit_char2",
	3: "named_curve",
}

var DictECCurveTypeNameIndexed = map[string]uint16{
	"explicit_prime": 1,
	"explicit_char2": 2,
	"named_curve":    3,
}
