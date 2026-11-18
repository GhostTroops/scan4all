package dicttls

// source: https://www.iana.org/assignments/quic/quic.xhtml#quic-transport
// last updated: July 2023

const (
	QUICTransportParameter_original_destination_connection_id  uint64 = 0x00
	QUICTransportParameter_max_idle_timeout                    uint64 = 0x01
	QUICTransportParameter_stateless_reset_token               uint64 = 0x02
	QUICTransportParameter_max_udp_payload_size                uint64 = 0x03
	QUICTransportParameter_initial_max_data                    uint64 = 0x04
	QUICTransportParameter_initial_max_stream_data_bidi_local  uint64 = 0x05
	QUICTransportParameter_initial_max_stream_data_bidi_remote uint64 = 0x06
	QUICTransportParameter_initial_max_stream_data_uni         uint64 = 0x07
	QUICTransportParameter_initial_max_streams_bidi            uint64 = 0x08
	QUICTransportParameter_initial_max_streams_uni             uint64 = 0x09
	QUICTransportParameter_ack_delay_exponent                  uint64 = 0x0a
	QUICTransportParameter_max_ack_delay                       uint64 = 0x0b
	QUICTransportParameter_disable_active_migration            uint64 = 0x0c
	QUICTransportParameter_preferred_address                   uint64 = 0x0d
	QUICTransportParameter_active_connection_id_limit          uint64 = 0x0e
	QUICTransportParameter_initial_source_connection_id        uint64 = 0x0f
	QUICTransportParameter_retry_source_connection_id          uint64 = 0x10
	QUICTransportParameter_version_information                 uint64 = 0x11   // RFC9368
	QUICTransportParameter_max_datagram_frame_size             uint64 = 0x20   // RFC9221
	QUICTransportParameter_discard                             uint64 = 0x173e // David_Schinazi: Receiver silently discards. https://github.com/quicwg/base-drafts/wiki/Quantum-Readiness-test
	QUICTransportParameter_google_handshake_message            uint64 = 0x26ab // Google: Used to carry Google internal handshake message
	QUICTransportParameter_grease_quic_bit                     uint64 = 0x2ab2 // RFC9287
	QUICTransportParameter_initial_rtt                         uint64 = 0x3127 // Google: Initial RTT in microseconds
	QUICTransportParameter_google_connection_options           uint64 = 0x3128 // Google: Google connection options for experimentation
	QUICTransportParameter_user_agent                          uint64 = 0x3129 // Google: User agent string (deprecated)
	QUICTransportParameter_google_version                      uint64 = 0x4752 // Google: Google QUIC version downgrade prevention
)

var DictQUICTransportParameterValueIndexed = map[uint64]string{
	0x00:   "original_destination_connection_id",
	0x01:   "max_idle_timeout",
	0x02:   "stateless_reset_token",
	0x03:   "max_udp_payload_size",
	0x04:   "initial_max_data",
	0x05:   "initial_max_stream_data_bidi_local",
	0x06:   "initial_max_stream_data_bidi_remote",
	0x07:   "initial_max_stream_data_uni",
	0x08:   "initial_max_streams_bidi",
	0x09:   "initial_max_streams_uni",
	0x0a:   "ack_delay_exponent",
	0x0b:   "max_ack_delay",
	0x0c:   "disable_active_migration",
	0x0d:   "preferred_address",
	0x0e:   "active_connection_id_limit",
	0x0f:   "initial_source_connection_id",
	0x10:   "retry_source_connection_id",
	0x11:   "version_information",
	0x20:   "max_datagram_frame_size",
	0x173e: "discard",
	0x26ab: "google handshake message",
	0x2ab2: "grease_quic_bit",
	0x3127: "initial_rtt",
	0x3128: "google_connection_options",
	0x3129: "user_agent",
	0x4752: "google_version",
}

var DictQUICTransportParameterNameIndexed = map[string]uint64{
	"original_destination_connection_id":  0x00,
	"max_idle_timeout":                    0x01,
	"stateless_reset_token":               0x02,
	"max_udp_payload_size":                0x03,
	"initial_max_data":                    0x04,
	"initial_max_stream_data_bidi_local":  0x05,
	"initial_max_stream_data_bidi_remote": 0x06,
	"initial_max_stream_data_uni":         0x07,
	"initial_max_streams_bidi":            0x08,
	"initial_max_streams_uni":             0x09,
	"ack_delay_exponent":                  0x0a,
	"max_ack_delay":                       0x0b,
	"disable_active_migration":            0x0c,
	"preferred_address":                   0x0d,
	"active_connection_id_limit":          0x0e,
	"initial_source_connection_id":        0x0f,
	"retry_source_connection_id":          0x10,
	"version_information":                 0x11,
	"max_datagram_frame_size":             0x20,
	"discard":                             0x173e,
	"google handshake message":            0x26ab,
	"grease_quic_bit":                     0x2ab2,
	"initial_rtt":                         0x3127,
	"google_connection_options":           0x3128,
	"user_agent":                          0x3129,
	"google_version":                      0x4752,
}
