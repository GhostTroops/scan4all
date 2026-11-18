package dicttls

// source: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-6
// last updated: March 2023

const (
	Alert_close_notify                    uint8 = 0
	Alert_unexpected_message              uint8 = 10
	Alert_bad_record_mac                  uint8 = 20
	Alert_decryption_failed               uint8 = 21
	Alert_record_overflow                 uint8 = 22
	Alert_decompression_failure           uint8 = 30
	Alert_handshake_failure               uint8 = 40
	Alert_no_certificate                  uint8 = 41
	Alert_bad_certificate                 uint8 = 42
	Alert_unsupported_certificate         uint8 = 43
	Alert_certificate_revoked             uint8 = 44
	Alert_certificate_expired             uint8 = 45
	Alert_certificate_unknown             uint8 = 46
	Alert_illegal_parameter               uint8 = 47
	Alert_unknown_ca                      uint8 = 48
	Alert_access_denied                   uint8 = 49
	Alert_decode_error                    uint8 = 50
	Alert_decrypt_error                   uint8 = 51
	Alert_too_many_cids_requested         uint8 = 52
	Alert_export_restriction              uint8 = 60
	Alert_protocol_version                uint8 = 70
	Alert_insufficient_security           uint8 = 71
	Alert_internal_error                  uint8 = 80
	Alert_inappropriate_fallback          uint8 = 86
	Alert_user_canceled                   uint8 = 90
	Alert_no_renegotiation                uint8 = 100
	Alert_missing_extension               uint8 = 109
	Alert_unsupported_extension           uint8 = 110
	Alert_certificate_unobtainable        uint8 = 111
	Alert_unrecognized_name               uint8 = 112
	Alert_bad_certificate_status_response uint8 = 113
	Alert_bad_certificate_hash_value      uint8 = 114
	Alert_unknown_psk_identity            uint8 = 115
	Alert_certificate_required            uint8 = 116
	Alert_no_application_protocol         uint8 = 120
)

var DictAlertValueIndexed = map[uint8]string{
	0:   "close_notify",
	10:  "unexpected_message",
	20:  "bad_record_mac",
	21:  "decryption_failed",
	22:  "record_overflow",
	30:  "decompression_failure",
	40:  "handshake_failure",
	41:  "no_certificate",
	42:  "bad_certificate",
	43:  "unsupported_certificate",
	44:  "certificate_revoked",
	45:  "certificate_expired",
	46:  "certificate_unknown",
	47:  "illegal_parameter",
	48:  "unknown_ca",
	49:  "access_denied",
	50:  "decode_error",
	51:  "decrypt_error",
	52:  "too_many_cids_requested",
	60:  "export_restriction",
	70:  "protocol_version",
	71:  "insufficient_security",
	80:  "internal_error",
	86:  "inappropriate_fallback",
	90:  "user_canceled",
	100: "no_renegotiation",
	109: "missing_extension",
	110: "unsupported_extension",
	111: "certificate_unobtainable",
	112: "unrecognized_name",
	113: "bad_certificate_status_response",
	114: "bad_certificate_hash_value",
	115: "unknown_psk_identity",
	116: "certificate_required",
	120: "no_application_protocol",
}

var DictAlertNameIndexed = map[string]uint8{
	"close_notify":                    0,
	"unexpected_message":              10,
	"bad_record_mac":                  20,
	"decryption_failed":               21,
	"record_overflow":                 22,
	"decompression_failure":           30,
	"handshake_failure":               40,
	"no_certificate":                  41,
	"bad_certificate":                 42,
	"unsupported_certificate":         43,
	"certificate_revoked":             44,
	"certificate_expired":             45,
	"certificate_unknown":             46,
	"illegal_parameter":               47,
	"unknown_ca":                      48,
	"access_denied":                   49,
	"decode_error":                    50,
	"decrypt_error":                   51,
	"too_many_cids_requested":         52,
	"export_restriction":              60,
	"protocol_version":                70,
	"insufficient_security":           71,
	"internal_error":                  80,
	"inappropriate_fallback":          86,
	"user_canceled":                   90,
	"no_renegotiation":                100,
	"missing_extension":               109,
	"unsupported_extension":           110,
	"certificate_unobtainable":        111,
	"unrecognized_name":               112,
	"bad_certificate_status_response": 113,
	"bad_certificate_hash_value":      114,
	"unknown_psk_identity":            115,
	"certificate_required":            116,
	"no_application_protocol":         120,
}
