package dicttls

// source: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-14
// last updated: March 2023

const (
	UserMappingType_upn_domain_hint uint8 = 64
)

var DictUserMappingTypeValueIndexed = map[uint8]string{
	64: "upn_domain_hint",
}

var DictUserMappingTypeNameIndexed = map[string]uint8{
	"upn_domain_hint": 64,
}
