package godicttls

// source: https://www.iana.org/assignments/tls-parameters/heartbeat-modes.csv
// last updated: March 2023

const (
	HeartbeatMode_peer_allowed_to_send     uint8 = 1
	HeartbeatMode_peer_not_allowed_to_send uint8 = 2
)

var DictHeartbeatModeValueIndexed = map[uint8]string{
	1: "peer_allowed_to_send",
	2: "peer_not_allowed_to_send",
}

var DictHeartbeatModeNameIndexed = map[string]uint8{
	"peer_allowed_to_send":     1,
	"peer_not_allowed_to_send": 2,
}
