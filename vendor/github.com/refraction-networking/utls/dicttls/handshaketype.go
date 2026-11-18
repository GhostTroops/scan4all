package dicttls

// source: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7
// last updated: March 2023

const (
	HandshakeType_hello_request              uint8 = 0
	HandshakeType_client_hello               uint8 = 1
	HandshakeType_server_hello               uint8 = 2
	HandshakeType_hello_verify_request       uint8 = 3
	HandshakeType_new_session_ticket         uint8 = 4
	HandshakeType_end_of_early_data          uint8 = 5
	HandshakeType_hello_retry_request        uint8 = 6
	HandshakeType_encrypted_extensions       uint8 = 8
	HandshakeType_request_connection_id      uint8 = 9
	HandshakeType_new_connection_id          uint8 = 10
	HandshakeType_certificate                uint8 = 11
	HandshakeType_server_key_exchange        uint8 = 12
	HandshakeType_certificate_request        uint8 = 13
	HandshakeType_server_hello_done          uint8 = 14
	HandshakeType_certificate_verify         uint8 = 15
	HandshakeType_client_key_exchange        uint8 = 16
	HandshakeType_client_certificate_request uint8 = 17
	HandshakeType_finished                   uint8 = 20
	HandshakeType_certificate_url            uint8 = 21
	HandshakeType_certificate_status         uint8 = 22
	HandshakeType_supplemental_data          uint8 = 23
	HandshakeType_key_update                 uint8 = 24
	HandshakeType_compressed_certificate     uint8 = 25
	HandshakeType_ekt_key                    uint8 = 26
	HandshakeType_message_hash               uint8 = 254

	// Not IANA assigned
	HandshakeType_next_protocol uint8 = 67
)

var DictHandshakeTypeValueIndexed = map[uint8]string{
	0:   "hello_request",
	1:   "client_hello",
	2:   "server_hello",
	3:   "hello_verify_request",
	4:   "new_session_ticket",
	5:   "end_of_early_data",
	6:   "hello_retry_request",
	7:   "Unassigned",
	8:   "encrypted_extensions",
	9:   "request_connection_id",
	10:  "new_connection_id",
	11:  "certificate",
	12:  "server_key_exchange",
	13:  "certificate_request",
	14:  "server_hello_done",
	15:  "certificate_verify",
	16:  "client_key_exchange",
	17:  "client_certificate_request",
	20:  "finished",
	21:  "certificate_url",
	22:  "certificate_status",
	23:  "supplemental_data",
	24:  "key_update",
	25:  "compressed_certificate",
	26:  "ekt_key",
	254: "message_hash",

	67: "next_protocol",
}

var DictHandshakeTypeNameIndexed = map[string]uint8{
	"hello_request":              0,
	"client_hello":               1,
	"server_hello":               2,
	"hello_verify_request":       3,
	"new_session_ticket":         4,
	"end_of_early_data":          5,
	"hello_retry_request":        6,
	"encrypted_extensions":       8,
	"request_connection_id":      9,
	"new_connection_id":          10,
	"certificate":                11,
	"server_key_exchange":        12,
	"certificate_request":        13,
	"server_hello_done":          14,
	"certificate_verify":         15,
	"client_key_exchange":        16,
	"client_certificate_request": 17,
	"finished":                   20,
	"certificate_url":            21,
	"certificate_status":         22,
	"supplemental_data":          23,
	"key_update":                 24,
	"compressed_certificate":     25,
	"ekt_key":                    26,
	"message_hash":               254,

	"next_protocol": 67,
}
