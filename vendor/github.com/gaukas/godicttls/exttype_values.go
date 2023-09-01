package godicttls

// source: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1
// last updated: March 2023

const (
	ExtType_server_name                            uint16 = 0
	ExtType_max_fragment_length                    uint16 = 1
	ExtType_client_certificate_url                 uint16 = 2
	ExtType_trusted_ca_keys                        uint16 = 3
	ExtType_truncated_hmac                         uint16 = 4
	ExtType_status_request                         uint16 = 5
	ExtType_user_mapping                           uint16 = 6
	ExtType_client_authz                           uint16 = 7
	ExtType_server_authz                           uint16 = 8
	ExtType_cert_type                              uint16 = 9
	ExtType_supported_groups                       uint16 = 10
	ExtType_ec_point_formats                       uint16 = 11
	ExtType_srp                                    uint16 = 12
	ExtType_signature_algorithms                   uint16 = 13
	ExtType_use_srtp                               uint16 = 14
	ExtType_heartbeat                              uint16 = 15
	ExtType_application_layer_protocol_negotiation uint16 = 16
	ExtType_status_request_v2                      uint16 = 17
	ExtType_signed_certificate_timestamp           uint16 = 18
	ExtType_client_certificate_type                uint16 = 19
	ExtType_server_certificate_type                uint16 = 20
	ExtType_padding                                uint16 = 21
	ExtType_encrypt_then_mac                       uint16 = 22
	ExtType_extended_master_secret                 uint16 = 23
	ExtType_token_binding                          uint16 = 24
	ExtType_cached_info                            uint16 = 25
	ExtType_tls_lts                                uint16 = 26
	ExtType_compress_certificate                   uint16 = 27
	ExtType_record_size_limit                      uint16 = 28
	ExtType_pwd_protect                            uint16 = 29
	ExtType_pwd_clear                              uint16 = 30
	ExtType_password_salt                          uint16 = 31
	ExtType_ticket_pinning                         uint16 = 32
	ExtType_tls_cert_with_extern_psk               uint16 = 33
	ExtType_delegated_credentials                  uint16 = 34 // IANA name: delegated_credentials, IETF name: delegated_credential
	ExtType_session_ticket                         uint16 = 35
	ExtType_TLMSP                                  uint16 = 36
	ExtType_TLMSP_proxying                         uint16 = 37
	ExtType_TLMSP_delegate                         uint16 = 38
	ExtType_supported_ekt_ciphers                  uint16 = 39
	ExtType_pre_shared_key                         uint16 = 41
	ExtType_early_data                             uint16 = 42
	ExtType_supported_versions                     uint16 = 43
	ExtType_cookie                                 uint16 = 44
	ExtType_psk_key_exchange_modes                 uint16 = 45
	ExtType_certificate_authorities                uint16 = 47
	ExtType_oid_filters                            uint16 = 48
	ExtType_post_handshake_auth                    uint16 = 49
	ExtType_signature_algorithms_cert              uint16 = 50
	ExtType_key_share                              uint16 = 51
	ExtType_transparency_info                      uint16 = 52
	ExtType_connection_id_deprecated               uint16 = 53 // deprecated
	ExtType_connection_id                          uint16 = 54
	ExtType_external_id_hash                       uint16 = 55
	ExtType_external_session_id                    uint16 = 56
	ExtType_quic_transport_parameters              uint16 = 57
	ExtType_ticket_request                         uint16 = 58
	ExtType_dnssec_chain                           uint16 = 59
	ExtType_renegotiation_info                     uint16 = 65281
)

// Not IANA assigned
const (
	ExtType_next_protocol_negotiation uint16 = 13172 // https://datatracker.ietf.org/doc/html/draft-agl-tls-nextprotoneg-04
	ExtType_application_settings      uint16 = 17513 // https://www.ietf.org/archive/id/draft-vvv-tls-alps-01.html
	ExtType_channel_id_old            uint16 = 30031 // https://datatracker.ietf.org/doc/html/draft-balfanz-tls-channelid-01
	ExtType_channel_id                uint16 = 30032 // https://datatracker.ietf.org/doc/html/draft-balfanz-tls-channelid-01
)

var DictExtTypeValueIndexed = map[uint16]string{
	0:     "server_name",
	1:     "max_fragment_length",
	2:     "client_certificate_url",
	3:     "trusted_ca_keys",
	4:     "truncated_hmac",
	5:     "status_request",
	6:     "user_mapping",
	7:     "client_authz",
	8:     "server_authz",
	9:     "cert_type",
	10:    "supported_groups",
	11:    "ec_point_formats",
	12:    "srp",
	13:    "signature_algorithms",
	14:    "use_srtp",
	15:    "heartbeat",
	16:    "application_layer_protocol_negotiation",
	17:    "status_request_v2",
	18:    "signed_certificate_timestamp",
	19:    "client_certificate_type",
	20:    "server_certificate_type",
	21:    "padding",
	22:    "encrypt_then_mac",
	23:    "extended_master_secret",
	24:    "token_binding",
	25:    "cached_info",
	26:    "tls_lts",
	27:    "compress_certificate",
	28:    "record_size_limit",
	29:    "pwd_protect",
	30:    "pwd_clear",
	31:    "password_salt",
	32:    "ticket_pinning",
	33:    "tls_cert_with_extern_psk",
	34:    "delegated_credentials", // IANA name: delegated_credentials, IETF name: delegated_credential
	35:    "session_ticket",
	36:    "TLMSP",
	37:    "TLMSP_proxying",
	38:    "TLMSP_delegate",
	39:    "supported_ekt_ciphers",
	41:    "pre_shared_key",
	42:    "early_data",
	43:    "supported_versions",
	44:    "cookie",
	45:    "psk_key_exchange_modes",
	47:    "certificate_authorities",
	48:    "oid_filters",
	49:    "post_handshake_auth",
	50:    "signature_algorithms_cert",
	51:    "key_share",
	52:    "transparency_info",
	53:    "connection_id_deprecated", // deprecated
	54:    "connection_id",
	55:    "external_id_hash",
	56:    "external_session_id",
	57:    "quic_transport_parameters",
	58:    "ticket_request",
	59:    "dnssec_chain",
	65281: "renegotiation_info",

	13172: "next_protocol_negotiation",
	17513: "application_settings",
	30031: "channel_id_old",
	30032: "channel_id",
}

var DictExtTypeNameIndexed = map[string]uint16{
	"server_name":                            0,
	"max_fragment_length":                    1,
	"client_certificate_url":                 2,
	"trusted_ca_keys":                        3,
	"truncated_hmac":                         4,
	"status_request":                         5,
	"user_mapping":                           6,
	"client_authz":                           7,
	"server_authz":                           8,
	"cert_type":                              9,
	"supported_groups":                       10,
	"ec_point_formats":                       11,
	"srp":                                    12,
	"signature_algorithms":                   13,
	"use_srtp":                               14,
	"heartbeat":                              15,
	"application_layer_protocol_negotiation": 16,
	"status_request_v2":                      17,
	"signed_certificate_timestamp":           18,
	"client_certificate_type":                19,
	"server_certificate_type":                20,
	"padding":                                21,
	"encrypt_then_mac":                       22,
	"extended_master_secret":                 23,
	"token_binding":                          24,
	"cached_info":                            25,
	"tls_lts":                                26,
	"compress_certificate":                   27,
	"record_size_limit":                      28,
	"pwd_protect":                            29,
	"pwd_clear":                              30,
	"password_salt":                          31,
	"ticket_pinning":                         32,
	"tls_cert_with_extern_psk":               33,
	"delegated_credentials":                  34, // IANA name: delegated_credentials
	"delegated_credential":                   34, // IETF name: delegated_credential
	"session_ticket":                         35,
	"TLMSP":                                  36,
	"TLMSP_proxying":                         37,
	"TLMSP_delegate":                         38,
	"supported_ekt_ciphers":                  39,
	"pre_shared_key":                         41,
	"early_data":                             42,
	"supported_versions":                     43,
	"cookie":                                 44,
	"psk_key_exchange_modes":                 45,
	"certificate_authorities":                47,
	"oid_filters":                            48,
	"post_handshake_auth":                    49,
	"signature_algorithms_cert":              50,
	"key_share":                              51,
	"transparency_info":                      52,
	"connection_id_deprecated":               53, // deprecated
	"connection_id":                          54,
	"external_id_hash":                       55,
	"external_session_id":                    56,
	"quic_transport_parameters":              57,
	"ticket_request":                         58,
	"dnssec_chain":                           59,
	"renegotiation_info":                     65281,

	"next_protocol_negotiation": 13172,
	"application_settings":      17513,
	"channel_id_old":            30031,
	"channel_id":                30032,
}
