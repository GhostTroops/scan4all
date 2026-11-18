package dicttls

// source: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-12
// last updated: March 2023

const (
	SupplementalDataType_user_mapping_data uint16 = 0
	SupplementalDataType_authz_data        uint16 = 16386
)

var DictSupplementalDataFormatValueIndexed = map[uint16]string{
	0:     "user_mapping_data",
	16386: "authz_data",
}

var DictSupplementalDataFormatNameIndexed = map[string]uint16{
	"user_mapping_data": 0,
	"authz_data":        16386,
}
