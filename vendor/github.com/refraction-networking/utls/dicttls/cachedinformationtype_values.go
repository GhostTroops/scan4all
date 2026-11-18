package dicttls

// source: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#cachedinformationtype
// last updated: March 2023

const (
	CachedInformationType_cert     uint8 = 1
	CachedInformationType_cert_req uint8 = 2
)

var DictCachedInformationTypeValueIndexed = map[uint8]string{
	1: "cert",
	2: "cert_req",
}

var DictCachedInformationTypeNameIndexed = map[string]uint8{
	"cert":     1,
	"cert_req": 2,
}
