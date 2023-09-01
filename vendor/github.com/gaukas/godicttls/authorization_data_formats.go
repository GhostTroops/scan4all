package godicttls

// source: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#authorization-data
// last updated: March 2023

const (
	AuthData_x509_attr_cert             uint16 = 0
	AuthData_saml_assertion             uint16 = 1
	AuthData_x509_attr_cert_url         uint16 = 2
	AuthData_saml_assertion_url         uint16 = 3
	AuthData_keynote_assertion_list     uint16 = 64
	AuthData_keynote_assertion_list_url uint16 = 65
	AuthData_dtcp_authorization         uint16 = 66
)

var DictAuthorizationDataFormatValueIndexed = map[uint16]string{
	0:  "x509_attr_cert",
	1:  "saml_assertion",
	2:  "x509_attr_cert_url",
	3:  "saml_assertion_url",
	64: "keynote_assertion_list",
	65: "keynote_assertion_list_url",
	66: "dtcp_authorization",
}

var DictAuthorizationDataFormatNameIndexed = map[string]uint16{
	"x509_attr_cert":             0,
	"saml_assertion":             1,
	"x509_attr_cert_url":         2,
	"saml_assertion_url":         3,
	"Unassigned":                 0,
	"keynote_assertion_list":     64,
	"keynote_assertion_list_url": 65,
	"dtcp_authorization":         66,
}
