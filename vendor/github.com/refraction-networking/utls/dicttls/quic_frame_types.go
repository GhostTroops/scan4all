package dicttls

// source: https://www.iana.org/assignments/quic/quic.xhtml#quic-frame-types
// last updated: July 2023

const (
	QUICFrameType_PADDING              uint8 = 0x00
	QUICFrameType_PING                 uint8 = 0x01
	QUICFrameType_ACK                  uint8 = 0x02
	QUICFrameType_ACK_ecn              uint8 = 0x03
	QUICFrameType_RESET_STREAM         uint8 = 0x04
	QUICFrameType_STOP_SENDING         uint8 = 0x05
	QUICFrameType_CRYPTO               uint8 = 0x06
	QUICFrameType_NEW_TOKEN            uint8 = 0x07
	QUICFrameType_STREAM               uint8 = 0x08
	QUICFrameType_STREAM_fin           uint8 = 0x09
	QUICFrameType_STREAM_len           uint8 = 0x0a
	QUICFrameType_STREAM_len_fin       uint8 = 0x0b
	QUICFrameType_STREAM_off           uint8 = 0x0c
	QUICFrameType_STREAM_off_fin       uint8 = 0x0d
	QUICFrameType_STREAM_off_len       uint8 = 0x0e
	QUICFrameType_STREAM_off_len_fin   uint8 = 0x0f
	QUICFrameType_MAX_DATA             uint8 = 0x10
	QUICFrameType_MAX_STREAM_DATA      uint8 = 0x11
	QUICFrameType_MAX_STREAMS_bidi     uint8 = 0x12
	QUICFrameType_MAX_STREAMS_uni      uint8 = 0x13
	QUICFrameType_DATA_BLOCKED         uint8 = 0x14
	QUICFrameType_STREAM_DATA_BLOCKED  uint8 = 0x15
	QUICFrameType_STREAMS_BLOCKED_bidi uint8 = 0x16
	QUICFrameType_STREAMS_BLOCKED_uni  uint8 = 0x17
	QUICFrameType_NEW_CONNECTION_ID    uint8 = 0x18
	QUICFrameType_RETIRE_CONNECTION_ID uint8 = 0x19
	QUICFrameType_PATH_CHALLENGE       uint8 = 0x1a
	QUICFrameType_PATH_RESPONSE        uint8 = 0x1b
	QUICFrameType_CONNECTION_CLOSE     uint8 = 0x1c
	QUICFrameType_CONNECTION_CLOSE_app uint8 = 0x1d
	QUICFrameType_HANDSHAKE_DONE       uint8 = 0x1e
	QUICFrameType_DATAGRAM             uint8 = 0x30 // RFC9221
	QUICFrameType_DATAGRAM_len         uint8 = 0x31 // RFC9221
)

var DictQUICFrameTypeValueIndexed = map[uint8]string{
	0x00: "PADDING",
	0x01: "PING",
	0x02: "ACK",
	0x03: "ACK_ecn",
	0x04: "RESET_STREAM",
	0x05: "STOP_SENDING",
	0x06: "CRYPTO",
	0x07: "NEW_TOKEN",
	0x08: "STREAM",
	0x09: "STREAM_fin",
	0x0a: "STREAM_len",
	0x0b: "STREAM_len_fin",
	0x0c: "STREAM_off",
	0x0d: "STREAM_off_fin",
	0x0e: "STREAM_off_len",
	0x0f: "STREAM_off_len_fin",
	0x10: "MAX_DATA",
	0x11: "MAX_STREAM_DATA",
	0x12: "MAX_STREAMS_bidi",
	0x13: "MAX_STREAMS_uni",
	0x14: "DATA_BLOCKED",
	0x15: "STREAM_DATA_BLOCKED",
	0x16: "STREAMS_BLOCKED_bidi",
	0x17: "STREAMS_BLOCKED_uni",
	0x18: "NEW_CONNECTION_ID",
	0x19: "RETIRE_CONNECTION_ID",
	0x1a: "PATH_CHALLENGE",
	0x1b: "PATH_RESPONSE",
	0x1c: "CONNECTION_CLOSE",
	0x1d: "CONNECTION_CLOSE_app",
	0x1e: "HANDSHAKE_DONE",
	0x30: "DATAGRAM",
	0x31: "DATAGRAM_len",
}

var DictQUICFrameTypeNameIndexed = map[string]uint8{
	"PADDING":              0x00,
	"PING":                 0x01,
	"ACK":                  0x02,
	"ACK_ecn":              0x03,
	"RESET_STREAM":         0x04,
	"STOP_SENDING":         0x05,
	"CRYPTO":               0x06,
	"NEW_TOKEN":            0x07,
	"STREAM":               0x08,
	"STREAM_fin":           0x09,
	"STREAM_len":           0x0a,
	"STREAM_len_fin":       0x0b,
	"STREAM_off":           0x0c,
	"STREAM_off_fin":       0x0d,
	"STREAM_off_len":       0x0e,
	"STREAM_off_len_fin":   0x0f,
	"MAX_DATA":             0x10,
	"MAX_STREAM_DATA":      0x11,
	"MAX_STREAMS_bidi":     0x12,
	"MAX_STREAMS_uni":      0x13,
	"DATA_BLOCKED":         0x14,
	"STREAM_DATA_BLOCKED":  0x15,
	"STREAMS_BLOCKED_bidi": 0x16,
	"STREAMS_BLOCKED_uni":  0x17,
	"NEW_CONNECTION_ID":    0x18,
	"RETIRE_CONNECTION_ID": 0x19,
	"PATH_CHALLENGE":       0x1a,
	"PATH_RESPONSE":        0x1b,
	"CONNECTION_CLOSE":     0x1c,
	"CONNECTION_CLOSE_app": 0x1d,
	"HANDSHAKE_DONE":       0x1e,
	"DATAGRAM":             0x30,
	"DATAGRAM_len":         0x31,
}
