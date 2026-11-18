package giop

// Header
// GIOP Header
type Header struct {
	Magic        []byte // 4
	MajorVersion []byte // 1
	MinorVersion []byte // 1
	MessageFlags []byte // 1
	MessageType  []byte // 1
	_messageSize []byte // 4
}
