package godicttls

// source: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-certificate-compression-algorithm-ids
// last updated: March 2023

const (
	CertCompAlg_zlib   uint16 = 1
	CertCompAlg_brotli uint16 = 2
	CertCompAlg_zstd   uint16 = 3
)

var DictCertificateCompressionAlgorithmValueIndexed = map[uint16]string{
	1: "zlib",
	2: "brotli",
	3: "zstd",
}

var DictCertificateCompressionAlgorithmNameIndexed = map[string]uint16{
	"zlib":   1,
	"brotli": 2,
	"zstd":   3,
}
