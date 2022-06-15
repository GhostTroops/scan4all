package ldapserver

import (
	"fmt"

	ldap "github.com/lor00x/goldap/message"
)

type Message struct {
	*ldap.LDAPMessage
	Client *client
	Done   chan bool
}

func (m *Message) String() string {
	return fmt.Sprintf("MessageId=%d, %s", m.MessageID(), m.ProtocolOpName())
}

// Abandon close the Done channel, to notify handler's user function to stop any
// running process
func (m *Message) Abandon() {
	m.Done <- true
}

func (m *Message) GetAbandonRequest() ldap.AbandonRequest {
	return m.ProtocolOp().(ldap.AbandonRequest)
}

func (m *Message) GetSearchRequest() ldap.SearchRequest {
	return m.ProtocolOp().(ldap.SearchRequest)
}

func (m *Message) GetBindRequest() ldap.BindRequest {
	return m.ProtocolOp().(ldap.BindRequest)
}

func (m *Message) GetAddRequest() ldap.AddRequest {
	return m.ProtocolOp().(ldap.AddRequest)
}

func (m *Message) GetDeleteRequest() ldap.DelRequest {
	return m.ProtocolOp().(ldap.DelRequest)
}

func (m *Message) GetModifyRequest() ldap.ModifyRequest {
	return m.ProtocolOp().(ldap.ModifyRequest)
}

func (m *Message) GetCompareRequest() ldap.CompareRequest {
	return m.ProtocolOp().(ldap.CompareRequest)
}

func (m *Message) GetExtendedRequest() ldap.ExtendedRequest {
	return m.ProtocolOp().(ldap.ExtendedRequest)
}
