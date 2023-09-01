package tls

import (
	"encoding/json"
	"errors"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

var ErrEmptyPsk = errors.New("tls: empty psk detected; remove the psk extension for this connection or set OmitEmptyPsk to true to conceal it in utls")

type PreSharedKeyCommon struct {
	Identities  []PskIdentity
	Binders     [][]byte
	BinderKey   []byte // this will be used to compute the binder when hello message is ready
	EarlySecret []byte
	Session     *SessionState
}

// The lifecycle of a PreSharedKeyExtension:
//
// Creation Phase:
//   - The extension is created.
//
// Write Phase:
//
//   - [writeToUConn() called]:
//
//     > - During this phase, it is important to note that implementations should not write any session data to the UConn (Underlying Connection) as the session is not yet loaded. The session context is not active at this point.
//
// Initialization Phase:
//
//   - [IsInitialized() called]:
//
//     If IsInitialized() returns true
//
//     > - GetPreSharedKeyCommon() will be called subsequently and the PSK states in handshake/clientHello will be fully initialized.
//
//     If IsInitialized() returns false:
//
//     > - [conn.loadSession() called]:
//
//     >> - Once the session is available:
//
//     >>> - [InitializeByUtls() called]:
//
//     >>>> - The InitializeByUtls() method is invoked to initialize the extension based on the loaded session data.
//
//     >>>> - This step prepares the extension for further processing.
//
// Marshal Phase:
//
//   - [Len() called], [Read() called]:
//
//     > - Implementations should marshal the extension into bytes, using placeholder binders to maintain the correct length.
//
// Binders Preparation Phase:
//
//   - [PatchBuiltHello(hello) called]:
//
//     > - The client hello is already marshaled in the "hello.Raw" format.
//
//     > - Implementations are expected to update the binders within the marshaled client hello.
//
//   - [GetPreSharedKeyCommon() called]:
//
//     > - Implementations should gather and provide the final pre-shared key (PSK) related data.
//
//     > - This data will be incorporated into both the clientHello and HandshakeState, ensuring that the PSK-related information is properly set and ready for the handshake process.
type PreSharedKeyExtension interface {
	// TLSExtension must be implemented by all PreSharedKeyExtension implementations.
	TLSExtension

	// If false is returned, utls will invoke `InitializeByUtls()` for the necessary initialization.
	Initializable

	SetOmitEmptyPsk(val bool)

	// InitializeByUtls is invoked when IsInitialized() returns false.
	// It initializes the extension using a real and valid TLS 1.3 session.
	InitializeByUtls(session *SessionState, earlySecret []byte, binderKey []byte, identities []PskIdentity)

	// GetPreSharedKeyCommon retrieves the final PreSharedKey-related states as defined in PreSharedKeyCommon.
	GetPreSharedKeyCommon() PreSharedKeyCommon

	// PatchBuiltHello is called once the hello message is fully applied and marshaled.
	// Its purpose is to update the binders of PSK (Pre-Shared Key) identities.
	PatchBuiltHello(hello *PubClientHelloMsg) error

	mustEmbedUnimplementedPreSharedKeyExtension() // this works like a type guard
}

type UnimplementedPreSharedKeyExtension struct{}

func (UnimplementedPreSharedKeyExtension) mustEmbedUnimplementedPreSharedKeyExtension() {}

func (*UnimplementedPreSharedKeyExtension) IsInitialized() bool {
	panic("tls: IsInitialized is not implemented for the PreSharedKeyExtension")
}

func (*UnimplementedPreSharedKeyExtension) InitializeByUtls(session *SessionState, earlySecret []byte, binderKey []byte, identities []PskIdentity) {
	panic("tls: Initialize is not implemented for the PreSharedKeyExtension")
}

func (*UnimplementedPreSharedKeyExtension) writeToUConn(*UConn) error {
	panic("tls: writeToUConn is not implemented for the PreSharedKeyExtension")
}

func (*UnimplementedPreSharedKeyExtension) Len() int {
	panic("tls: Len is not implemented for the PreSharedKeyExtension")
}

func (*UnimplementedPreSharedKeyExtension) Read([]byte) (int, error) {
	panic("tls: Read is not implemented for the PreSharedKeyExtension")
}

func (*UnimplementedPreSharedKeyExtension) GetPreSharedKeyCommon() PreSharedKeyCommon {
	panic("tls: GetPreSharedKeyCommon is not implemented for the PreSharedKeyExtension")
}

func (*UnimplementedPreSharedKeyExtension) PatchBuiltHello(hello *PubClientHelloMsg) error {
	panic("tls: ReadWithRawHello is not implemented for the PreSharedKeyExtension")
}

func (*UnimplementedPreSharedKeyExtension) SetOmitEmptyPsk(val bool) {
	panic("tls: SetOmitEmptyPsk is not implemented for the PreSharedKeyExtension")
}

// UtlsPreSharedKeyExtension is an extension used to set the PSK extension in the
// ClientHello.
type UtlsPreSharedKeyExtension struct {
	UnimplementedPreSharedKeyExtension
	PreSharedKeyCommon
	cipherSuite  *cipherSuiteTLS13
	cachedLength *int
	OmitEmptyPsk bool
}

func (e *UtlsPreSharedKeyExtension) IsInitialized() bool {
	return e.Session != nil
}

func (e *UtlsPreSharedKeyExtension) InitializeByUtls(session *SessionState, earlySecret []byte, binderKey []byte, identities []PskIdentity) {
	e.Session = session
	e.EarlySecret = earlySecret
	e.BinderKey = binderKey
	e.cipherSuite = cipherSuiteTLS13ByID(e.Session.cipherSuite)
	e.Identities = identities
	e.Binders = make([][]byte, 0, len(e.Identities))
	for i := 0; i < len(e.Identities); i++ {
		e.Binders = append(e.Binders, make([]byte, e.cipherSuite.hash.Size()))
	}
}

func (e *UtlsPreSharedKeyExtension) writeToUConn(uc *UConn) error {
	uc.HandshakeState.Hello.TicketSupported = true // This doesn't matter though, as utls doesn't care about this field. We write this for consistency.
	return nil
}

func (e *UtlsPreSharedKeyExtension) GetPreSharedKeyCommon() PreSharedKeyCommon {
	return e.PreSharedKeyCommon
}

func pskExtLen(identities []PskIdentity, binders [][]byte) int {
	if len(identities) == 0 || len(binders) == 0 {
		// If there isn't psk identities, we don't write this ticket to the client hello, and therefore the length should be 0.
		return 0
	}
	length := 4 // extension type + extension length
	length += 2 // identities length
	for _, identity := range identities {
		length += 2 + len(identity.Label) + 4 // identity length + identity + obfuscated ticket age
	}
	length += 2 // binders length
	for _, binder := range binders {
		length += len(binder) + 1
	}
	return length
}

func (e *UtlsPreSharedKeyExtension) Len() int {
	if e.Session == nil {
		return 0
	}
	if e.cachedLength != nil {
		return *e.cachedLength
	}
	length := pskExtLen(e.Identities, e.Binders)
	e.cachedLength = &length
	return length
}

func readPskIntoBytes(b []byte, identities []PskIdentity, binders [][]byte) (int, error) {
	extLen := pskExtLen(identities, binders)
	if extLen == 0 {
		return 0, io.EOF
	}
	if len(b) < extLen {
		return 0, io.ErrShortBuffer
	}

	b[0] = byte(extensionPreSharedKey >> 8)
	b[1] = byte(extensionPreSharedKey)
	b[2] = byte((extLen - 4) >> 8)
	b[3] = byte(extLen - 4)

	// identities length
	identitiesLength := 0
	for _, identity := range identities {
		identitiesLength += 2 + len(identity.Label) + 4 // identity length + identity + obfuscated ticket age
	}
	b[4] = byte(identitiesLength >> 8)
	b[5] = byte(identitiesLength)

	// identities
	offset := 6
	for _, identity := range identities {
		b[offset] = byte(len(identity.Label) >> 8)
		b[offset+1] = byte(len(identity.Label))
		offset += 2
		copy(b[offset:], identity.Label)
		offset += len(identity.Label)
		b[offset] = byte(identity.ObfuscatedTicketAge >> 24)
		b[offset+1] = byte(identity.ObfuscatedTicketAge >> 16)
		b[offset+2] = byte(identity.ObfuscatedTicketAge >> 8)
		b[offset+3] = byte(identity.ObfuscatedTicketAge)
		offset += 4
	}

	// binders length
	bindersLength := 0
	for _, binder := range binders {
		// check if binder size is valid
		bindersLength += len(binder) + 1 // binder length + binder
	}
	b[offset] = byte(bindersLength >> 8)
	b[offset+1] = byte(bindersLength)
	offset += 2

	// binders
	for _, binder := range binders {
		b[offset] = byte(len(binder))
		offset++
		copy(b[offset:], binder)
		offset += len(binder)
	}

	return extLen, io.EOF
}

func (e *UtlsPreSharedKeyExtension) SetOmitEmptyPsk(val bool) {
	e.OmitEmptyPsk = val
}

func (e *UtlsPreSharedKeyExtension) Read(b []byte) (int, error) {
	if !e.OmitEmptyPsk && e.Len() == 0 {
		return 0, ErrEmptyPsk
	}
	return readPskIntoBytes(b, e.Identities, e.Binders)
}

func (e *UtlsPreSharedKeyExtension) PatchBuiltHello(hello *PubClientHelloMsg) error {
	if e.Len() == 0 {
		return nil
	}
	private := hello.getCachedPrivatePtr()
	if private == nil {
		private = hello.getPrivatePtr()
	}
	private.raw = hello.Raw
	private.pskBinders = e.Binders // set the placeholder to the private Hello

	//--- mirror loadSession() begin ---//
	transcript := e.cipherSuite.hash.New()
	helloBytes, err := private.marshalWithoutBinders() // no marshal() will be actually called, as we have set the field `raw`
	if err != nil {
		return err
	}
	transcript.Write(helloBytes)
	pskBinders := [][]byte{e.cipherSuite.finishedHash(e.BinderKey, transcript)}

	if err := private.updateBinders(pskBinders); err != nil {
		return err
	}
	//--- mirror loadSession() end ---//
	e.Binders = pskBinders

	// no need to care about other PSK related fields, they will be handled separately

	return io.EOF
}

func (e *UtlsPreSharedKeyExtension) Write(b []byte) (int, error) {
	return len(b), nil // ignore the data
}

func (e *UtlsPreSharedKeyExtension) UnmarshalJSON(_ []byte) error {
	return nil // ignore the data
}

// FakePreSharedKeyExtension is an extension used to set the PSK extension in the
// ClientHello.
//
// It does not compute binders based on ClientHello, but uses the binders specified instead.
// We still need to learn more of the safety
// of hardcoding both Identities and Binders without recalculating the latter.
type FakePreSharedKeyExtension struct {
	UnimplementedPreSharedKeyExtension

	Identities   []PskIdentity `json:"identities"`
	Binders      [][]byte      `json:"binders"`
	OmitEmptyPsk bool
}

func (e *FakePreSharedKeyExtension) IsInitialized() bool {
	return e.Identities != nil && e.Binders != nil
}

func (e *FakePreSharedKeyExtension) InitializeByUtls(session *SessionState, earlySecret []byte, binderKey []byte, identities []PskIdentity) {
	panic("InitializeByUtls failed: don't let utls initialize FakePreSharedKeyExtension; provide your own identities and binders or use UtlsPreSharedKeyExtension")
}

func (e *FakePreSharedKeyExtension) writeToUConn(uc *UConn) error {
	if uc.config.ClientSessionCache == nil {
		return nil // don't write the extension if there is no session cache
	}
	if session, ok := uc.config.ClientSessionCache.Get(uc.clientSessionCacheKey()); !ok || session == nil {
		return nil // don't write the extension if there is no session cache available for this session
	}
	uc.HandshakeState.Hello.PskIdentities = e.Identities
	uc.HandshakeState.Hello.PskBinders = e.Binders
	return nil
}

func (e *FakePreSharedKeyExtension) Len() int {
	return pskExtLen(e.Identities, e.Binders)
}

func (e *FakePreSharedKeyExtension) SetOmitEmptyPsk(val bool) {
	e.OmitEmptyPsk = val
}

func (e *FakePreSharedKeyExtension) Read(b []byte) (int, error) {
	if !e.OmitEmptyPsk && e.Len() == 0 {
		return 0, ErrEmptyPsk
	}
	for _, b := range e.Binders {
		if !(anyTrue(validHashLen, func(_ int, valid *int) bool {
			return len(b) == *valid
		})) {
			return 0, errors.New("tls: FakePreSharedKeyExtension.Read failed: invalid binder size")
		}
	}

	return readPskIntoBytes(b, e.Identities, e.Binders)
}

func (e *FakePreSharedKeyExtension) GetPreSharedKeyCommon() PreSharedKeyCommon {
	return PreSharedKeyCommon{
		Identities: e.Identities,
		Binders:    e.Binders,
	}
}

var validHashLen = mapSlice(cipherSuitesTLS13, func(c *cipherSuiteTLS13) int {
	return c.hash.Size()
})

func (*FakePreSharedKeyExtension) PatchBuiltHello(*PubClientHelloMsg) error {
	return nil // no need to patch the hello since we don't need to update binders
}

func (e *FakePreSharedKeyExtension) Write(b []byte) (n int, err error) {
	fullLen := len(b)
	s := cryptobyte.String(b)

	var identitiesLength uint16
	if !s.ReadUint16(&identitiesLength) {
		return 0, errors.New("tls: invalid PSK extension")
	}

	// identities
	for identitiesLength > 0 {
		var identityLength uint16
		if !s.ReadUint16(&identityLength) {
			return 0, errors.New("tls: invalid PSK extension")
		}
		identitiesLength -= 2

		if identityLength > identitiesLength {
			return 0, errors.New("tls: invalid PSK extension")
		}

		var identity []byte
		if !s.ReadBytes(&identity, int(identityLength)) {
			return 0, errors.New("tls: invalid PSK extension")
		}

		identitiesLength -= identityLength // identity

		var obfuscatedTicketAge uint32
		if !s.ReadUint32(&obfuscatedTicketAge) {
			return 0, errors.New("tls: invalid PSK extension")
		}

		e.Identities = append(e.Identities, PskIdentity{
			Label:               identity,
			ObfuscatedTicketAge: obfuscatedTicketAge,
		})

		identitiesLength -= 4 // obfuscated ticket age
	}

	var bindersLength uint16
	if !s.ReadUint16(&bindersLength) {
		return 0, errors.New("tls: invalid PSK extension")
	}

	// binders
	for bindersLength > 0 {
		var binderLength uint8
		if !s.ReadUint8(&binderLength) {
			return 0, errors.New("tls: invalid PSK extension")
		}
		bindersLength -= 1

		if uint16(binderLength) > bindersLength {
			return 0, errors.New("tls: invalid PSK extension")
		}

		var binder []byte
		if !s.ReadBytes(&binder, int(binderLength)) {
			return 0, errors.New("tls: invalid PSK extension")
		}

		e.Binders = append(e.Binders, binder)

		bindersLength -= uint16(binderLength)
	}

	return fullLen, nil
}

func (e *FakePreSharedKeyExtension) UnmarshalJSON(data []byte) error {
	var pskAccepter struct {
		PskIdentities []PskIdentity `json:"identities"`
		PskBinders    [][]byte      `json:"binders"`
	}

	if err := json.Unmarshal(data, &pskAccepter); err != nil {
		return err
	}

	e.Identities = pskAccepter.PskIdentities
	e.Binders = pskAccepter.PskBinders
	return nil
}

// type guard
var (
	_ PreSharedKeyExtension = (*UtlsPreSharedKeyExtension)(nil)
	_ TLSExtensionJSON      = (*UtlsPreSharedKeyExtension)(nil)
	_ PreSharedKeyExtension = (*FakePreSharedKeyExtension)(nil)
	_ TLSExtensionJSON      = (*FakePreSharedKeyExtension)(nil)
	_ TLSExtensionWriter    = (*FakePreSharedKeyExtension)(nil)
)

// type ExternalPreSharedKeyExtension struct{} // TODO: wait for whoever cares about external PSK to implement it
