package message

func NewLDAPMessageWithProtocolOp(po ProtocolOp) *LDAPMessage {
	m := NewLDAPMessage()
	m.protocolOp = po
	return m
}
