package dicttls

// source: https://www.iana.org/assignments/quic/quic.xhtml#quic-transport-error-codes
// last updated: July 2023

const (
	QUICTransportErrorCode_NO_ERROR                  uint16 = 0x0000
	QUICTransportErrorCode_INTERNAL_ERROR            uint16 = 0x0001
	QUICTransportErrorCode_CONNECTION_REFUSED        uint16 = 0x0002
	QUICTransportErrorCode_FLOW_CONTROL_ERROR        uint16 = 0x0003
	QUICTransportErrorCode_STREAM_LIMIT_ERROR        uint16 = 0x0004
	QUICTransportErrorCode_STREAM_STATE_ERROR        uint16 = 0x0005
	QUICTransportErrorCode_FINAL_SIZE_ERROR          uint16 = 0x0006
	QUICTransportErrorCode_FRAME_ENCODING_ERROR      uint16 = 0x0007
	QUICTransportErrorCode_TRANSPORT_PARAMETER_ERROR uint16 = 0x0008
	QUICTransportErrorCode_CONNECTION_ID_LIMIT_ERROR uint16 = 0x0009
	QUICTransportErrorCode_PROTOCOL_VIOLATION        uint16 = 0x000A
	QUICTransportErrorCode_INVALID_TOKEN             uint16 = 0x000B
	QUICTransportErrorCode_APPLICATION_ERROR         uint16 = 0x000C
	QUICTransportErrorCode_CRYPTO_BUFFER_EXCEEDED    uint16 = 0x000D
	QUICTransportErrorCode_KEY_UPDATE_ERROR          uint16 = 0x000E
	QUICTransportErrorCode_AEAD_LIMIT_REACHED        uint16 = 0x000F
	QUICTransportErrorCode_NO_VIABLE_PATH            uint16 = 0x0010
	QUICTransportErrorCode_VERSION_NEGOTIATION_ERROR uint16 = 0x0011 // RFC9368
	QUICTransportErrorCode_CRYPTO_ERROR              uint16 = 0x0100 // 0x0100-0x01FF, use with bitwise operator
)

var DictQUICTransportErrorCodeValueIndexed = map[uint16]string{
	0x0000: "NO_ERROR",
	0x0001: "INTERNAL_ERROR",
	0x0002: "CONNECTION_REFUSED",
	0x0003: "FLOW_CONTROL_ERROR",
	0x0004: "STREAM_LIMIT_ERROR",
	0x0005: "STREAM_STATE_ERROR",
	0x0006: "FINAL_SIZE_ERROR",
	0x0007: "FRAME_ENCODING_ERROR",
	0x0008: "TRANSPORT_PARAMETER_ERROR",
	0x0009: "CONNECTION_ID_LIMIT_ERROR",
	0x000A: "PROTOCOL_VIOLATION",
	0x000B: "INVALID_TOKEN",
	0x000C: "APPLICATION_ERROR",
	0x000D: "CRYPTO_BUFFER_EXCEEDED",
	0x000E: "KEY_UPDATE_ERROR",
	0x000F: "AEAD_LIMIT_REACHED",
	0x0010: "NO_VIABLE_PATH",
	0x0011: "VERSION_NEGOTIATION_ERROR",
	0x0100: "CRYPTO_ERROR",
}

var DictQUICTransportErrorCodeNameIndexed = map[string]uint16{
	"NO_ERROR":                  0x0000,
	"INTERNAL_ERROR":            0x0001,
	"CONNECTION_REFUSED":        0x0002,
	"FLOW_CONTROL_ERROR":        0x0003,
	"STREAM_LIMIT_ERROR":        0x0004,
	"STREAM_STATE_ERROR":        0x0005,
	"FINAL_SIZE_ERROR":          0x0006,
	"FRAME_ENCODING_ERROR":      0x0007,
	"TRANSPORT_PARAMETER_ERROR": 0x0008,
	"CONNECTION_ID_LIMIT_ERROR": 0x0009,
	"PROTOCOL_VIOLATION":        0x000A,
	"INVALID_TOKEN":             0x000B,
	"APPLICATION_ERROR":         0x000C,
	"CRYPTO_BUFFER_EXCEEDED":    0x000D,
	"KEY_UPDATE_ERROR":          0x000E,
	"AEAD_LIMIT_REACHED":        0x000F,
	"NO_VIABLE_PATH":            0x0010,
	"VERSION_NEGOTIATION_ERROR": 0x0011,
	"CRYPTO_ERROR":              0x0100,
}
