// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/x509"
	"hash"
	"time"
)

// ClientHandshakeState includes both TLS 1.3-only and TLS 1.2-only states,
// only one of them will be used, depending on negotiated version.
//
// ClientHandshakeState will be converted into and from either
//   - clientHandshakeState      (TLS 1.2)
//   - clientHandshakeStateTLS13 (TLS 1.3)
//
// uTLS will call .handshake() on one of these private internal states,
// to perform TLS handshake using standard crypto/tls implementation.
type PubClientHandshakeState struct {
	C            *Conn
	ServerHello  *PubServerHelloMsg
	Hello        *PubClientHelloMsg
	MasterSecret []byte
	Session      *SessionState

	State12 TLS12OnlyState
	State13 TLS13OnlyState

	uconn *UConn
}

// TLS 1.3 only
type TLS13OnlyState struct {
	// Deprecated: Use KeyShareKeys instead. KeyShareKeys will take precedence if both are set.
	// Support may be removed in the future.
	EcdheKey *ecdh.PrivateKey
	// Deprecated: Use KeyShareKeys instead. This variable is no longer used.
	// Will be removed in the future.
	KeySharesParams *KeySharesParameters
	// Deprecated: Use KeyShareKeys instead. This variable is no longer used.
	// Will be removed in the future.
	KEMKey *KemPrivateKey

	KeyShareKeys  *KeySharePrivateKeys
	Suite         *PubCipherSuiteTLS13
	EarlySecret   []byte
	BinderKey     []byte
	CertReq       *CertificateRequestMsgTLS13
	UsingPSK      bool // don't set this field when building client hello
	SentDummyCCS  bool
	Transcript    hash.Hash
	TrafficSecret []byte // client_application_traffic_secret_0
}

// TLS 1.2 and before only
type TLS12OnlyState struct {
	FinishedHash FinishedHash
	Suite        PubCipherSuite
}

func (chs *TLS13OnlyState) private13KeyShareKeys() *keySharePrivateKeys {
	if chs.KeyShareKeys != nil {
		return chs.KeyShareKeys.ToPrivate()
	}

	if chs.EcdheKey != nil {
		return &keySharePrivateKeys{
			ecdhe: chs.EcdheKey,
		}
	}

	return nil
}

// func kyberGoToCircl(kyberKey *mlkem768.DecapsulationKey, ecdhKey *ecdh.PrivateKey) (kem.PrivateKey, error) {
// 	return hybrid.Kyber768X25519().UnmarshalBinaryPrivateKey(append(ecdhKey.Bytes(), kyberKey.Bytes()...))
// }

func (chs *PubClientHandshakeState) toPrivate13() *clientHandshakeStateTLS13 {
	if chs == nil {
		return nil
	} else {
		return &clientHandshakeStateTLS13{
			c:            chs.C,
			serverHello:  chs.ServerHello.getPrivatePtr(),
			hello:        chs.Hello.getPrivatePtr(),
			keyShareKeys: chs.State13.private13KeyShareKeys(),

			session:   chs.Session,
			binderKey: chs.State13.BinderKey,

			certReq:       chs.State13.CertReq.toPrivate(),
			usingPSK:      chs.State13.UsingPSK,
			sentDummyCCS:  chs.State13.SentDummyCCS,
			suite:         chs.State13.Suite.toPrivate(),
			transcript:    chs.State13.Transcript,
			trafficSecret: chs.State13.TrafficSecret,

			uconn: chs.uconn,
		}
	}
}

func (chs13 *clientHandshakeStateTLS13) toPublic13() *PubClientHandshakeState {
	if chs13 == nil {
		return nil
	} else {
		tls13State := TLS13OnlyState{
			KeyShareKeys:  chs13.keyShareKeys.ToPublic(),
			EarlySecret:   chs13.earlySecret.Secret(),
			BinderKey:     chs13.binderKey,
			CertReq:       chs13.certReq.toPublic(),
			UsingPSK:      chs13.usingPSK,
			SentDummyCCS:  chs13.sentDummyCCS,
			Suite:         chs13.suite.toPublic(),
			TrafficSecret: chs13.trafficSecret,
			Transcript:    chs13.transcript,
		}
		return &PubClientHandshakeState{
			C:           chs13.c,
			ServerHello: chs13.serverHello.getPublicPtr(),
			Hello:       chs13.hello.getPublicPtr(),

			Session: chs13.session,

			MasterSecret: chs13.masterSecret.Secret(),

			State13: tls13State,

			uconn: chs13.uconn,
		}
	}
}

func (chs *PubClientHandshakeState) toPrivate12() *clientHandshakeState {
	if chs == nil {
		return nil
	} else {
		return &clientHandshakeState{
			c:           chs.C,
			serverHello: chs.ServerHello.getPrivatePtr(),
			hello:       chs.Hello.getPrivatePtr(),
			suite:       chs.State12.Suite.getPrivatePtr(),
			session:     chs.Session,

			masterSecret: chs.MasterSecret,

			finishedHash: chs.State12.FinishedHash.getPrivateObj(),

			uconn: chs.uconn,
		}
	}
}

func (chs12 *clientHandshakeState) toPublic12() *PubClientHandshakeState {
	if chs12 == nil {
		return nil
	} else {
		tls12State := TLS12OnlyState{
			Suite:        chs12.suite.getPublicObj(),
			FinishedHash: chs12.finishedHash.getPublicObj(),
		}
		return &PubClientHandshakeState{
			C:           chs12.c,
			ServerHello: chs12.serverHello.getPublicPtr(),
			Hello:       chs12.hello.getPublicPtr(),

			Session: chs12.session,

			MasterSecret: chs12.masterSecret,

			State12: tls12State,

			uconn: chs12.uconn,
		}
	}
}

// type EcdheParameters interface {
// 	ecdheParameters
// }

type CertificateRequestMsgTLS13 struct {
	// Deprecated: crypto/tls no longer use this variable. This field won't be read or used by utls, but will still be populated.
	// Support may be removed in the future.
	Raw []byte

	OcspStapling                     bool
	Scts                             bool
	SupportedSignatureAlgorithms     []SignatureScheme
	SupportedSignatureAlgorithmsCert []SignatureScheme
	CertificateAuthorities           [][]byte
}

func (crm *certificateRequestMsgTLS13) toPublic() *CertificateRequestMsgTLS13 {
	if crm == nil {
		return nil
	} else {
		rawBytes := []byte{}
		if raw, err := crm.marshal(); err == nil {
			rawBytes = raw
		}

		return &CertificateRequestMsgTLS13{
			Raw:                              rawBytes,
			OcspStapling:                     crm.ocspStapling,
			Scts:                             crm.scts,
			SupportedSignatureAlgorithms:     crm.supportedSignatureAlgorithms,
			SupportedSignatureAlgorithmsCert: crm.supportedSignatureAlgorithmsCert,
			CertificateAuthorities:           crm.certificateAuthorities,
		}
	}
}

func (crm *CertificateRequestMsgTLS13) toPrivate() *certificateRequestMsgTLS13 {
	if crm == nil {
		return nil
	} else {
		return &certificateRequestMsgTLS13{
			ocspStapling:                     crm.OcspStapling,
			scts:                             crm.Scts,
			supportedSignatureAlgorithms:     crm.SupportedSignatureAlgorithms,
			supportedSignatureAlgorithmsCert: crm.SupportedSignatureAlgorithmsCert,
			certificateAuthorities:           crm.CertificateAuthorities,
		}
	}
}

type PubCipherSuiteTLS13 struct {
	Id     uint16
	KeyLen int
	Aead   func(key, fixedNonce []byte) aead
	Hash   crypto.Hash
}

func (c *cipherSuiteTLS13) toPublic() *PubCipherSuiteTLS13 {
	if c == nil {
		return nil
	} else {
		return &PubCipherSuiteTLS13{
			Id:     c.id,
			KeyLen: c.keyLen,
			Aead:   c.aead,
			Hash:   c.hash,
		}
	}
}

func (c *PubCipherSuiteTLS13) toPrivate() *cipherSuiteTLS13 {
	if c == nil {
		return nil
	} else {
		return &cipherSuiteTLS13{
			id:     c.Id,
			keyLen: c.KeyLen,
			aead:   c.Aead,
			hash:   c.Hash,
		}
	}
}

type PubServerHelloMsg struct {
	Raw                          []byte // renamed to serverHelloMsg.original in crypto/tls
	Vers                         uint16
	Random                       []byte
	SessionId                    []byte
	CipherSuite                  uint16
	CompressionMethod            uint8
	NextProtoNeg                 bool
	NextProtos                   []string
	OcspStapling                 bool
	Scts                         [][]byte
	ExtendedMasterSecret         bool
	TicketSupported              bool // used by go tls to determine whether to add the session ticket ext
	SecureRenegotiation          []byte
	SecureRenegotiationSupported bool
	AlpnProtocol                 string

	// 1.3
	SupportedVersion        uint16
	ServerShare             KeyShare
	SelectedIdentityPresent bool
	SelectedIdentity        uint16
	Cookie                  []byte  // HelloRetryRequest extension
	SelectedGroup           CurveID // HelloRetryRequest extension

}

func (shm *PubServerHelloMsg) getPrivatePtr() *serverHelloMsg {
	if shm == nil {
		return nil
	} else {
		return &serverHelloMsg{
			original:                     shm.Raw,
			vers:                         shm.Vers,
			random:                       shm.Random,
			sessionId:                    shm.SessionId,
			cipherSuite:                  shm.CipherSuite,
			compressionMethod:            shm.CompressionMethod,
			nextProtoNeg:                 shm.NextProtoNeg,
			nextProtos:                   shm.NextProtos,
			ocspStapling:                 shm.OcspStapling,
			scts:                         shm.Scts,
			extendedMasterSecret:         shm.ExtendedMasterSecret,
			ticketSupported:              shm.TicketSupported,
			secureRenegotiation:          shm.SecureRenegotiation,
			secureRenegotiationSupported: shm.SecureRenegotiationSupported,
			alpnProtocol:                 shm.AlpnProtocol,
			supportedVersion:             shm.SupportedVersion,
			serverShare:                  shm.ServerShare.ToPrivate(),
			selectedIdentityPresent:      shm.SelectedIdentityPresent,
			selectedIdentity:             shm.SelectedIdentity,
			cookie:                       shm.Cookie,
			selectedGroup:                shm.SelectedGroup,
		}
	}
}

func (shm *serverHelloMsg) getPublicPtr() *PubServerHelloMsg {
	if shm == nil {
		return nil
	} else {
		return &PubServerHelloMsg{
			Raw:                          shm.original,
			Vers:                         shm.vers,
			Random:                       shm.random,
			SessionId:                    shm.sessionId,
			CipherSuite:                  shm.cipherSuite,
			CompressionMethod:            shm.compressionMethod,
			NextProtoNeg:                 shm.nextProtoNeg,
			NextProtos:                   shm.nextProtos,
			OcspStapling:                 shm.ocspStapling,
			Scts:                         shm.scts,
			ExtendedMasterSecret:         shm.extendedMasterSecret,
			TicketSupported:              shm.ticketSupported,
			SecureRenegotiation:          shm.secureRenegotiation,
			SecureRenegotiationSupported: shm.secureRenegotiationSupported,
			AlpnProtocol:                 shm.alpnProtocol,
			SupportedVersion:             shm.supportedVersion,
			ServerShare:                  shm.serverShare.ToPublic(),
			SelectedIdentityPresent:      shm.selectedIdentityPresent,
			SelectedIdentity:             shm.selectedIdentity,
			Cookie:                       shm.cookie,
			SelectedGroup:                shm.selectedGroup,
		}
	}
}

type PubClientHelloMsg struct {
	Raw                          []byte // renamed to clientHelloMsg.original in crypto/tls
	Vers                         uint16
	Random                       []byte
	SessionId                    []byte
	CipherSuites                 []uint16
	CompressionMethods           []uint8
	NextProtoNeg                 bool
	ServerName                   string
	OcspStapling                 bool
	Scts                         bool
	Ems                          bool // [uTLS] actually implemented due to its prevalence
	SupportedCurves              []CurveID
	SupportedPoints              []uint8
	TicketSupported              bool
	SessionTicket                []uint8
	SupportedSignatureAlgorithms []SignatureScheme
	SecureRenegotiation          []byte
	SecureRenegotiationSupported bool
	AlpnProtocols                []string

	// 1.3
	SupportedSignatureAlgorithmsCert []SignatureScheme
	SupportedVersions                []uint16
	Cookie                           []byte
	KeyShares                        []KeyShare
	EarlyData                        bool
	PskModes                         []uint8
	PskIdentities                    []PskIdentity
	PskBinders                       [][]byte
	QuicTransportParameters          []byte

	cachedPrivateHello   *clientHelloMsg // todo: further optimize to reduce clientHelloMsg construction
	encryptedClientHello []byte
}

func (chm *PubClientHelloMsg) getPrivatePtr() *clientHelloMsg {
	if chm == nil {
		return nil
	} else {
		private := &clientHelloMsg{
			original:                         chm.Raw,
			vers:                             chm.Vers,
			random:                           chm.Random,
			sessionId:                        chm.SessionId,
			cipherSuites:                     chm.CipherSuites,
			compressionMethods:               chm.CompressionMethods,
			serverName:                       chm.ServerName,
			ocspStapling:                     chm.OcspStapling,
			supportedCurves:                  chm.SupportedCurves,
			supportedPoints:                  chm.SupportedPoints,
			ticketSupported:                  chm.TicketSupported,
			sessionTicket:                    chm.SessionTicket,
			supportedSignatureAlgorithms:     chm.SupportedSignatureAlgorithms,
			supportedSignatureAlgorithmsCert: chm.SupportedSignatureAlgorithmsCert,
			secureRenegotiationSupported:     chm.SecureRenegotiationSupported,
			secureRenegotiation:              chm.SecureRenegotiation,
			extendedMasterSecret:             chm.Ems,
			alpnProtocols:                    chm.AlpnProtocols,
			scts:                             chm.Scts,

			supportedVersions:       chm.SupportedVersions,
			cookie:                  chm.Cookie,
			keyShares:               KeyShares(chm.KeyShares).ToPrivate(),
			earlyData:               chm.EarlyData,
			pskModes:                chm.PskModes,
			pskIdentities:           PskIdentities(chm.PskIdentities).ToPrivate(),
			pskBinders:              chm.PskBinders,
			quicTransportParameters: chm.QuicTransportParameters,
			encryptedClientHello:    chm.encryptedClientHello,

			nextProtoNeg: chm.NextProtoNeg,
		}
		chm.cachedPrivateHello = private
		return private
	}
}

func (chm *PubClientHelloMsg) getCachedPrivatePtr() *clientHelloMsg {
	if chm == nil {
		return nil
	} else {
		return chm.cachedPrivateHello
	}
}

func (chm *clientHelloMsg) getPublicPtr() *PubClientHelloMsg {
	if chm == nil {
		return nil
	} else {
		return &PubClientHelloMsg{
			Raw:                          chm.original,
			Vers:                         chm.vers,
			Random:                       chm.random,
			SessionId:                    chm.sessionId,
			CipherSuites:                 chm.cipherSuites,
			CompressionMethods:           chm.compressionMethods,
			NextProtoNeg:                 chm.nextProtoNeg,
			ServerName:                   chm.serverName,
			OcspStapling:                 chm.ocspStapling,
			Scts:                         chm.scts,
			Ems:                          chm.extendedMasterSecret,
			SupportedCurves:              chm.supportedCurves,
			SupportedPoints:              chm.supportedPoints,
			TicketSupported:              chm.ticketSupported,
			SessionTicket:                chm.sessionTicket,
			SupportedSignatureAlgorithms: chm.supportedSignatureAlgorithms,
			SecureRenegotiation:          chm.secureRenegotiation,
			SecureRenegotiationSupported: chm.secureRenegotiationSupported,
			AlpnProtocols:                chm.alpnProtocols,

			SupportedSignatureAlgorithmsCert: chm.supportedSignatureAlgorithmsCert,
			SupportedVersions:                chm.supportedVersions,
			Cookie:                           chm.cookie,
			KeyShares:                        keyShares(chm.keyShares).ToPublic(),
			EarlyData:                        chm.earlyData,
			PskModes:                         chm.pskModes,
			PskIdentities:                    pskIdentities(chm.pskIdentities).ToPublic(),
			PskBinders:                       chm.pskBinders,
			QuicTransportParameters:          chm.quicTransportParameters,
			cachedPrivateHello:               chm,
			encryptedClientHello:             chm.encryptedClientHello,
		}
	}
}

// UnmarshalClientHello allows external code to parse raw client hellos.
// It returns nil on failure.
func UnmarshalClientHello(data []byte) *PubClientHelloMsg {
	m := &clientHelloMsg{}
	if m.unmarshal(data) {
		return m.getPublicPtr()
	}
	return nil
}

// Marshal allows external code to convert a ClientHello object back into
// raw bytes.
func (chm *PubClientHelloMsg) Marshal() ([]byte, error) {
	return chm.getPrivatePtr().marshal()
}

// A CipherSuite is a specific combination of key agreement, cipher and MAC
// function. All cipher suites currently assume RSA key agreement.
type PubCipherSuite struct {
	Id uint16
	// the lengths, in bytes, of the key material needed for each component.
	KeyLen int
	MacLen int
	IvLen  int
	Ka     func(version uint16) keyAgreement
	// flags is a bitmask of the suite* values, above.
	Flags  int
	Cipher func(key, iv []byte, isRead bool) interface{}
	Mac    func(macKey []byte) hash.Hash
	Aead   func(key, fixedNonce []byte) aead
}

func (cs *PubCipherSuite) getPrivatePtr() *cipherSuite {
	if cs == nil {
		return nil
	} else {
		return &cipherSuite{
			id:     cs.Id,
			keyLen: cs.KeyLen,
			macLen: cs.MacLen,
			ivLen:  cs.IvLen,
			ka:     cs.Ka,
			flags:  cs.Flags,
			cipher: cs.Cipher,
			mac:    cs.Mac,
			aead:   cs.Aead,
		}
	}
}

func (cs *cipherSuite) getPublicObj() PubCipherSuite {
	if cs == nil {
		return PubCipherSuite{}
	} else {
		return PubCipherSuite{
			Id:     cs.id,
			KeyLen: cs.keyLen,
			MacLen: cs.macLen,
			IvLen:  cs.ivLen,
			Ka:     cs.ka,
			Flags:  cs.flags,
			Cipher: cs.cipher,
			Mac:    cs.mac,
			Aead:   cs.aead,
		}
	}
}

// A FinishedHash calculates the hash of a set of handshake messages suitable
// for including in a Finished message.
type FinishedHash struct {
	Client hash.Hash
	Server hash.Hash

	// Prior to TLS 1.2, an additional MD5 hash is required.
	ClientMD5 hash.Hash
	ServerMD5 hash.Hash

	// In TLS 1.2, a full buffer is sadly required.
	Buffer []byte

	Version uint16
	Prfv2   prfFunc

	// Deprecated: Use Prfv2 instead. Prfv2 will be used if both are set.
	Prf prfFuncOld
}

type prfFuncOld func(result, secret, label, seed []byte)

func prfFuncV1ToV2(v1 prfFuncOld) prfFunc {
	return func(secret []byte, label string, seed []byte, keyLen int) []byte {
		res := make([]byte, keyLen)
		v1(res, secret, []byte(label), seed)
		return res
	}
}

func prfFuncV2ToV1(v2 prfFunc) prfFuncOld {
	return func(result, secret, label, seed []byte) {
		copy(result, v2(secret, string(label), seed, len(result)))
	}
}

func (fh *FinishedHash) getPrivateObj() finishedHash {
	if fh == nil {
		return finishedHash{}
	} else {
		res := finishedHash{
			client:    fh.Client,
			server:    fh.Server,
			clientMD5: fh.ClientMD5,
			serverMD5: fh.ServerMD5,
			buffer:    fh.Buffer,
			version:   fh.Version,
		}

		if fh.Prfv2 != nil {
			res.prf = fh.Prfv2
		} else if fh.Prf != nil {
			res.prf = prfFuncV1ToV2(fh.Prf)
		}

		return res
	}
}

func (fh *finishedHash) getPublicObj() FinishedHash {
	if fh == nil {
		return FinishedHash{}
	} else {
		res := FinishedHash{
			Client:    fh.client,
			Server:    fh.server,
			ClientMD5: fh.clientMD5,
			ServerMD5: fh.serverMD5,
			Buffer:    fh.buffer,
			Version:   fh.version,
		}

		res.Prfv2 = fh.prf
		res.Prf = prfFuncV2ToV1(fh.prf)

		return res
	}
}

// TLS 1.3 Key Share. See RFC 8446, Section 4.2.8.
type KeyShare struct {
	Group CurveID `json:"group"`
	Data  []byte  `json:"key_exchange,omitempty"` // optional
}

func (ks KeyShare) ToPrivate() keyShare {
	return keyShare{group: ks.Group, data: ks.Data}
}

func (ks keyShare) ToPublic() KeyShare {
	return KeyShare{Group: ks.group, Data: ks.data}
}

type KeyShares []KeyShare
type keyShares []keyShare

func (kss keyShares) ToPublic() []KeyShare {
	var KSS []KeyShare
	for _, ks := range kss {
		KSS = append(KSS, ks.ToPublic())
	}
	return KSS
}
func (KSS KeyShares) ToPrivate() []keyShare {
	var kss []keyShare
	for _, KS := range KSS {
		kss = append(kss, KS.ToPrivate())
	}
	return kss
}

// TLS 1.3 PSK Identity. Can be a Session Ticket, or a reference to a saved
// session. See RFC 8446, Section 4.2.11.
type PskIdentity struct {
	Label               []byte `json:"identity"`
	ObfuscatedTicketAge uint32 `json:"obfuscated_ticket_age"`
}

type PskIdentities []PskIdentity
type pskIdentities []pskIdentity

func (pss pskIdentities) ToPublic() []PskIdentity {
	var PSS []PskIdentity
	for _, ps := range pss {
		PSS = append(PSS, PskIdentity{Label: ps.label, ObfuscatedTicketAge: ps.obfuscatedTicketAge})
	}
	return PSS
}

func (PSS PskIdentities) ToPrivate() []pskIdentity {
	var pss []pskIdentity
	for _, PS := range PSS {
		pss = append(pss, pskIdentity{label: PS.Label, obfuscatedTicketAge: PS.ObfuscatedTicketAge})
	}
	return pss
}

// ClientSessionState is public, but all its fields are private. Let's add setters, getters and constructor

// ClientSessionState contains the state needed by clients to resume TLS sessions.
func MakeClientSessionState(
	SessionTicket []uint8,
	Vers uint16,
	CipherSuite uint16,
	MasterSecret []byte,
	ServerCertificates []*x509.Certificate,
	VerifiedChains [][]*x509.Certificate) *ClientSessionState {
	// TODO: Add EMS to this constructor in uTLS v2
	css := &ClientSessionState{
		session: &SessionState{
			version:          Vers,
			cipherSuite:      CipherSuite,
			secret:           MasterSecret,
			peerCertificates: ServerCertificates,
			verifiedChains:   VerifiedChains,
			ticket:           SessionTicket,
		},
	}
	return css
}

// Encrypted ticket used for session resumption with server
func (css *ClientSessionState) SessionTicket() []uint8 {
	return css.session.ticket
}

// SSL/TLS version negotiated for the session
func (css *ClientSessionState) Vers() uint16 {
	return css.session.version
}

// Ciphersuite negotiated for the session
func (css *ClientSessionState) CipherSuite() uint16 {
	return css.session.cipherSuite
}

// MasterSecret generated by client on a full handshake
func (css *ClientSessionState) MasterSecret() []byte {
	return css.session.secret
}

func (css *ClientSessionState) EMS() bool {
	return css.session.extMasterSecret
}

// Certificate chain presented by the server
func (css *ClientSessionState) ServerCertificates() []*x509.Certificate {
	return css.session.peerCertificates
}

// Certificate chains we built for verification
func (css *ClientSessionState) VerifiedChains() [][]*x509.Certificate {
	return css.session.verifiedChains
}

func (css *ClientSessionState) SetSessionTicket(SessionTicket []uint8) {
	css.session.ticket = SessionTicket
}

func (css *ClientSessionState) SetVers(Vers uint16) {
	if css.session == nil {
		css.session = &SessionState{}
	}
	css.session.version = Vers
}

func (css *ClientSessionState) SetCipherSuite(CipherSuite uint16) {
	if css.session == nil {
		css.session = &SessionState{}
	}
	css.session.cipherSuite = CipherSuite
}

func (css *ClientSessionState) SetCreatedAt(createdAt uint64) {
	if css.session == nil {
		css.session = &SessionState{}
	}
	css.session.createdAt = createdAt
}

func (css *ClientSessionState) SetMasterSecret(MasterSecret []byte) {
	if css.session == nil {
		css.session = &SessionState{}
	}
	css.session.secret = MasterSecret
}

func (css *ClientSessionState) SetEMS(ems bool) {
	if css.session == nil {
		css.session = &SessionState{}
	}
	css.session.extMasterSecret = ems
}

func (css *ClientSessionState) SetServerCertificates(ServerCertificates []*x509.Certificate) {
	if css.session == nil {
		css.session = &SessionState{}
	}
	css.session.peerCertificates = ServerCertificates
}

func (css *ClientSessionState) SetVerifiedChains(VerifiedChains [][]*x509.Certificate) {
	if css.session == nil {
		css.session = &SessionState{}
	}
	css.session.verifiedChains = VerifiedChains
}

func (css *ClientSessionState) SetUseBy(useBy uint64) {
	if css.session == nil {
		css.session = &SessionState{}
	}
	css.session.useBy = useBy
}

func (css *ClientSessionState) SetAgeAdd(ageAdd uint32) {
	if css.session == nil {
		css.session = &SessionState{}
	}
	css.session.ageAdd = ageAdd
}

// TicketKey is the internal representation of a session ticket key.
type TicketKey struct {
	AesKey  [16]byte
	HmacKey [16]byte
	// created is the time at which this ticket key was created. See Config.ticketKeys.
	Created time.Time
}

type TicketKeys []TicketKey
type ticketKeys []ticketKey

func TicketKeyFromBytes(b [32]byte) TicketKey {
	// [uTLS]
	// empty config is required
	config := &Config{}
	tk := config.ticketKeyFromBytes(b)
	return tk.ToPublic()
}

func (tk ticketKey) ToPublic() TicketKey {
	return TicketKey{
		AesKey:  tk.aesKey,
		HmacKey: tk.hmacKey,
		Created: tk.created,
	}
}

func (TK TicketKey) ToPrivate() ticketKey {
	return ticketKey{
		aesKey:  TK.AesKey,
		hmacKey: TK.HmacKey,
		created: TK.Created,
	}
}

func (tks ticketKeys) ToPublic() []TicketKey {
	var TKS []TicketKey
	for _, ks := range tks {
		TKS = append(TKS, ks.ToPublic())
	}
	return TKS
}

func (TKS TicketKeys) ToPrivate() []ticketKey {
	var tks []ticketKey
	for _, TK := range TKS {
		tks = append(tks, TK.ToPrivate())
	}
	return tks
}

type kemPrivateKey struct {
	secretKey any
	curveID   CurveID
}

// Deprecated: Use KeySharePrivateKeys instead. This type is no longer used.
// Will be removed in the future.
type KemPrivateKey struct {
	SecretKey any
	CurveID   CurveID
}

func (kpk *KemPrivateKey) ToPrivate() *kemPrivateKey {
	if kpk == nil {
		return nil
	} else {
		return &kemPrivateKey{
			secretKey: kpk.SecretKey,
			curveID:   kpk.CurveID,
		}
	}
}

func (kpk *kemPrivateKey) ToPublic() *KemPrivateKey {
	if kpk == nil {
		return nil
	} else {
		return &KemPrivateKey{
			SecretKey: kpk.secretKey,
			CurveID:   kpk.curveID,
		}
	}
}

type KeySharePrivateKeys struct {
	CurveID    CurveID
	Ecdhe      *ecdh.PrivateKey
	Mlkem      *mlkem.DecapsulationKey768
	MlkemEcdhe *ecdh.PrivateKey
}

func (ksp *KeySharePrivateKeys) ToPrivate() *keySharePrivateKeys {
	if ksp == nil {
		return nil
	}
	return &keySharePrivateKeys{
		curveID:    ksp.CurveID,
		ecdhe:      ksp.Ecdhe,
		mlkem:      ksp.Mlkem,
		mlkemEcdhe: ksp.MlkemEcdhe,
	}
}

func (ksp *keySharePrivateKeys) ToPublic() *KeySharePrivateKeys {
	if ksp == nil {
		return nil
	}
	return &KeySharePrivateKeys{
		CurveID:    ksp.curveID,
		Ecdhe:      ksp.ecdhe,
		Mlkem:      ksp.mlkem,
		MlkemEcdhe: ksp.mlkemEcdhe,
	}
}
