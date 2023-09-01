package godicttls

// source: https://www.iana.org/assignments/tls-parameters/heartbeat-message-types.csv
// last updated: March 2023

const (
	HeartbeatMessage_request  uint8 = 1
	HeartbeatMessage_response uint8 = 2
)

var DictHeartbeatMessageTypeValueIndexed = map[uint8]string{
	1: "heartbeat_request",
	2: "heartbeat_response",
}

var DictHeartbeatMessageTypeNameIndexed = map[string]uint8{
	"heartbeat_request":  1,
	"heartbeat_response": 2,
}
