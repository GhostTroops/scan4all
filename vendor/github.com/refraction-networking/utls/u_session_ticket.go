package tls

import "io"

type ISessionTicketExtension interface {
	TLSExtension

	// If false is returned, utls will invoke `InitializeByUtls()` for the necessary initialization.
	Initializable

	// InitializeByUtls is invoked when IsInitialized() returns false.
	// It initializes the extension using a real and valid TLS 1.2 session.
	InitializeByUtls(session *SessionState, ticket []byte)

	GetSession() *SessionState

	GetTicket() []byte
}

// SessionTicketExtension implements session_ticket (35)
type SessionTicketExtension struct {
	Session     *SessionState
	Ticket      []byte
	Initialized bool
}

func (e *SessionTicketExtension) writeToUConn(uc *UConn) error {
	// session states are handled later. At this point tickets aren't
	// being loaded by utls, so don't write anything to the UConn.
	uc.HandshakeState.Hello.TicketSupported = true // This doesn't really matter, this field is only used to add session ticket ext in go tls.
	return nil
}

func (e *SessionTicketExtension) Len() int {
	return 4 + len(e.Ticket)
}

func (e *SessionTicketExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	extBodyLen := e.Len() - 4

	b[0] = byte(extensionSessionTicket >> 8)
	b[1] = byte(extensionSessionTicket)
	b[2] = byte(extBodyLen >> 8)
	b[3] = byte(extBodyLen)
	if extBodyLen > 0 {
		copy(b[4:], e.Ticket)
	}
	return e.Len(), io.EOF
}

func (e *SessionTicketExtension) IsInitialized() bool {
	return e.Initialized
}

func (e *SessionTicketExtension) InitializeByUtls(session *SessionState, ticket []byte) {
	uAssert(!e.Initialized, "tls: InitializeByUtls failed: the SessionTicketExtension is initialized")
	uAssert(session.version == VersionTLS12 && session != nil && ticket != nil, "tls: InitializeByUtls failed: the session is not a tls 1.2 session")
	e.Session = session
	e.Ticket = ticket
	e.Initialized = true
}

func (e *SessionTicketExtension) UnmarshalJSON(_ []byte) error {
	return nil // no-op
}

func (e *SessionTicketExtension) Write(_ []byte) (int, error) {
	// RFC 5077, Section 3.2
	return 0, nil
}

func (e *SessionTicketExtension) GetSession() *SessionState {
	return e.Session
}

func (e *SessionTicketExtension) GetTicket() []byte {
	return e.Ticket
}
