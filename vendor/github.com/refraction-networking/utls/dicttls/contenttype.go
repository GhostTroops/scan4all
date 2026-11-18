package dicttls

// source: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5
// last updated: March 2023

const (
	ContentType_change_cipher_spec uint8 = 20
	ContentType_alert              uint8 = 21
	ContentType_handshake          uint8 = 22
	ContentType_application_data   uint8 = 23
	ContentType_heartbeat          uint8 = 24
	ContentType_tls12_cid          uint8 = 25
	ContentType_ACK                uint8 = 26
)

var DictContentTypeValueIndexed = map[uint8]string{
	20: "change_cipher_spec",
	21: "alert",
	22: "handshake",
	23: "application_data",
	24: "heartbeat",
	25: "tls12_cid",
	26: "ACK",
}

var DictContentTypeNameIndexed = map[string]uint8{
	"change_cipher_spec": 20,
	"alert":              21,
	"handshake":          22,
	"application_data":   23,
	"heartbeat":          24,
	"tls12_cid":          25,
	"ACK":                26,
}
