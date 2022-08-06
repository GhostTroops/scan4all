package socks5

const (
	// Ver is socks protocol version
	Ver byte = 0x05

	// MethodNone is none method
	MethodNone byte = 0x00
	// MethodGSSAPI is gssapi method
	MethodGSSAPI byte = 0x01 // MUST support // todo
	// MethodUsernamePassword is username/assword auth method
	MethodUsernamePassword byte = 0x02 // SHOULD support
	// MethodUnsupportAll means unsupport all given methods
	MethodUnsupportAll byte = 0xFF

	// UserPassVer is username/password auth protocol version
	UserPassVer byte = 0x01
	// UserPassStatusSuccess is success status of username/password auth
	UserPassStatusSuccess byte = 0x00
	// UserPassStatusFailure is failure status of username/password auth
	UserPassStatusFailure byte = 0x01 // just other than 0x00

	// CmdConnect is connect command
	CmdConnect byte = 0x01
	// CmdBind is bind command
	CmdBind byte = 0x02
	// CmdUDP is UDP command
	CmdUDP byte = 0x03

	// ATYPIPv4 is ipv4 address type
	ATYPIPv4 byte = 0x01 // 4 octets
	// ATYPDomain is domain address type
	ATYPDomain byte = 0x03 // The first octet of the address field contains the number of octets of name that follow, there is no terminating NUL octet.
	// ATYPIPv6 is ipv6 address type
	ATYPIPv6 byte = 0x04 // 16 octets

	// RepSuccess means that success for repling
	RepSuccess byte = 0x00
	// RepServerFailure means the server failure
	RepServerFailure byte = 0x01
	// RepNotAllowed means the request not allowed
	RepNotAllowed byte = 0x02
	// RepNetworkUnreachable means the network unreachable
	RepNetworkUnreachable byte = 0x03
	// RepHostUnreachable means the host unreachable
	RepHostUnreachable byte = 0x04
	// RepConnectionRefused means the connection refused
	RepConnectionRefused byte = 0x05
	// RepTTLExpired means the TTL expired
	RepTTLExpired byte = 0x06
	// RepCommandNotSupported means the request command not supported
	RepCommandNotSupported byte = 0x07
	// RepAddressNotSupported means the request address not supported
	RepAddressNotSupported byte = 0x08
)

// NegotiationRequest is the negotiation reqeust packet
type NegotiationRequest struct {
	Ver      byte
	NMethods byte
	Methods  []byte // 1-255 bytes
}

// NegotiationReply is the negotiation reply packet
type NegotiationReply struct {
	Ver    byte
	Method byte
}

// UserPassNegotiationRequest is the negotiation username/password reqeust packet
type UserPassNegotiationRequest struct {
	Ver    byte
	Ulen   byte
	Uname  []byte // 1-255 bytes
	Plen   byte
	Passwd []byte // 1-255 bytes
}

// UserPassNegotiationReply is the negotiation username/password reply packet
type UserPassNegotiationReply struct {
	Ver    byte
	Status byte
}

// Request is the request packet
type Request struct {
	Ver     byte
	Cmd     byte
	Rsv     byte // 0x00
	Atyp    byte
	DstAddr []byte
	DstPort []byte // 2 bytes
}

// Reply is the reply packet
type Reply struct {
	Ver  byte
	Rep  byte
	Rsv  byte // 0x00
	Atyp byte
	// CONNECT socks server's address which used to connect to dst addr
	// BIND ...
	// UDP socks server's address which used to connect to dst addr
	BndAddr []byte
	// CONNECT socks server's port which used to connect to dst addr
	// BIND ...
	// UDP socks server's port which used to connect to dst addr
	BndPort []byte // 2 bytes
}

// Datagram is the UDP packet
type Datagram struct {
	Rsv     []byte // 0x00 0x00
	Frag    byte
	Atyp    byte
	DstAddr []byte
	DstPort []byte // 2 bytes
	Data    []byte
}
