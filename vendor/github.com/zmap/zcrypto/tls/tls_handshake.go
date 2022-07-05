// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	jsonKeys "github.com/zmap/zcrypto/json"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/ct"
)

var ErrUnimplementedCipher error = errors.New("unimplemented cipher suite")
var ErrNoMutualCipher error = errors.New("no mutual cipher suite")

type TLSVersion uint16

type CipherSuite uint16

type ClientHello struct {
	Version              TLSVersion          `json:"version"`
	Random               []byte              `json:"random"`
	SessionID            []byte              `json:"session_id,omitempty"`
	CipherSuites         []CipherSuite       `json:"cipher_suites"`
	CompressionMethods   []CompressionMethod `json:"compression_methods"`
	OcspStapling         bool                `json:"ocsp_stapling"`
	TicketSupported      bool                `json:"ticket"`
	SecureRenegotiation  bool                `json:"secure_renegotiation"`
	HeartbeatSupported   bool                `json:"heartbeat"`
	ExtendedRandom       []byte              `json:"extended_random,omitempty"`
	ExtendedMasterSecret bool                `json:"extended_master_secret"`
	NextProtoNeg         bool                `json:"next_protocol_negotiation"`
	ServerName           string              `json:"server_name,omitempty"`
	Scts                 bool                `json:"scts"`
	SupportedCurves      []CurveID           `json:"supported_curves,omitempty"`
	SupportedPoints      []PointFormat       `json:"supported_point_formats,omitempty"`
	SessionTicket        *SessionTicket      `json:"session_ticket,omitempty"`
	SignatureAndHashes   []SignatureAndHash  `json:"signature_and_hashes,omitempty"`
	SctEnabled           bool                `json:"sct_enabled"`
	AlpnProtocols        []string            `json:"alpn_protocols,omitempty"`
	UnknownExtensions    [][]byte            `json:"unknown_extensions,omitempty"`
}

type ParsedAndRawSCT struct {
	Raw    []byte                         `json:"raw,omitempty"`
	Parsed *ct.SignedCertificateTimestamp `json:"parsed,omitempty"`
}

type ServerHello struct {
	Version     TLSVersion  `json:"version"`
	Random      []byte      `json:"random"`
	SessionID   []byte      `json:"session_id"`
	CipherSuite CipherSuite `json:"cipher_suite"`
	// TODO FIXME: Why is this a raw uint8, not a CompressionMethod?
	CompressionMethod           uint8             `json:"compression_method"`
	OcspStapling                bool              `json:"ocsp_stapling"`
	TicketSupported             bool              `json:"ticket"`
	SecureRenegotiation         bool              `json:"secure_renegotiation"`
	HeartbeatSupported          bool              `json:"heartbeat"`
	ExtendedRandom              []byte            `json:"extended_random,omitempty"`
	ExtendedMasterSecret        bool              `json:"extended_master_secret"`
	SignedCertificateTimestamps []ParsedAndRawSCT `json:"scts,omitempty"`
	AlpnProtocol                string            `json:"alpn_protocol,omitempty"`
}

// SimpleCertificate holds a *x509.Certificate and a []byte for the certificate
type SimpleCertificate struct {
	Raw    []byte            `json:"raw,omitempty"`
	Parsed *x509.Certificate `json:"parsed,omitempty"`
}

// Certificates represents a TLS certificates message in a format friendly to the golang JSON library.
// ValidationError should be non-nil whenever Valid is false.
type Certificates struct {
	Certificate SimpleCertificate   `json:"certificate,omitempty"`
	Chain       []SimpleCertificate `json:"chain,omitempty"`
	Validation  *x509.Validation    `json:"validation,omitempty"`
}

// ServerKeyExchange represents the raw key data sent by the server in TLS key exchange message
type ServerKeyExchange struct {
	Raw            []byte                 `json:"-"`
	RSAParams      *jsonKeys.RSAPublicKey `json:"rsa_params,omitempty"`
	DHParams       *jsonKeys.DHParams     `json:"dh_params,omitempty"`
	ECDHParams     *jsonKeys.ECDHParams   `json:"ecdh_params,omitempty"`
	Digest         []byte                 `json:"digest,omitempty"`
	Signature      *DigitalSignature      `json:"signature,omitempty"`
	SignatureError string                 `json:"signature_error,omitempty"`
}

// ClientKeyExchange represents the raw key data sent by the client in TLS key exchange message
type ClientKeyExchange struct {
	Raw        []byte                    `json:"-"`
	RSAParams  *jsonKeys.RSAClientParams `json:"rsa_params,omitempty"`
	DHParams   *jsonKeys.DHParams        `json:"dh_params,omitempty"`
	ECDHParams *jsonKeys.ECDHParams      `json:"ecdh_params,omitempty"`
}

// Finished represents a TLS Finished message
type Finished struct {
	VerifyData []byte `json:"verify_data"`
}

// SessionTicket represents the new session ticket sent by the server to the
// client
type SessionTicket struct {
	Value        []uint8 `json:"value,omitempty"`
	Length       int     `json:"length,omitempty"`
	LifetimeHint uint32  `json:"lifetime_hint,omitempty"`
}

type MasterSecret struct {
	Value  []byte `json:"value,omitempty"`
	Length int    `json:"length,omitempty"`
}

type PreMasterSecret struct {
	Value  []byte `json:"value,omitempty"`
	Length int    `json:"length,omitempty"`
}

// KeyMaterial explicitly represent the cryptographic values negotiated by
// the client and server
type KeyMaterial struct {
	MasterSecret    *MasterSecret    `json:"master_secret,omitempty"`
	PreMasterSecret *PreMasterSecret `json:"pre_master_secret,omitempty"`
}

// ServerHandshake stores all of the messages sent by the server during a standard TLS Handshake.
// It implements zgrab.EventData interface
type ServerHandshake struct {
	ClientHello        *ClientHello       `json:"client_hello,omitempty" zgrab:"debug"`
	ServerHello        *ServerHello       `json:"server_hello,omitempty"`
	ServerCertificates *Certificates      `json:"server_certificates,omitempty"`
	ServerKeyExchange  *ServerKeyExchange `json:"server_key_exchange,omitempty"`
	ClientKeyExchange  *ClientKeyExchange `json:"client_key_exchange,omitempty"`
	ClientFinished     *Finished          `json:"client_finished,omitempty"`
	SessionTicket      *SessionTicket     `json:"session_ticket,omitempty"`
	ServerFinished     *Finished          `json:"server_finished,omitempty"`
	KeyMaterial        *KeyMaterial       `json:"key_material,omitempty"`
}

// MarshalJSON implements the json.Marshler interface
func (v *TLSVersion) MarshalJSON() ([]byte, error) {
	aux := struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}{
		Name:  v.String(),
		Value: int(*v),
	}
	return json.Marshal(&aux)
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (v *TLSVersion) UnmarshalJSON(b []byte) error {
	aux := struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*v = TLSVersion(aux.Value)
	if expectedName := v.String(); expectedName != aux.Name {
		return fmt.Errorf("mismatched tls version and name: version: %d, name: %s, expected name: %s", aux.Value, aux.Name, expectedName)
	}
	return nil
}

// MarshalJSON implements the json.Marshler interface
func (cs *CipherSuite) MarshalJSON() ([]byte, error) {
	buf := make([]byte, 2)
	buf[0] = byte(*cs >> 8)
	buf[1] = byte(*cs)
	enc := strings.ToUpper(hex.EncodeToString(buf))
	aux := struct {
		Hex   string `json:"hex"`
		Name  string `json:"name"`
		Value int    `json:"value"`
	}{
		Hex:   fmt.Sprintf("0x%s", enc),
		Name:  cs.String(),
		Value: int(*cs),
	}
	return json.Marshal(&aux)
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (cs *CipherSuite) UnmarshalJSON(b []byte) error {
	aux := struct {
		Hex   string `json:"hex"`
		Name  string `json:"name"`
		Value uint16 `json:"value"`
	}{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	if expectedName := nameForSuite(aux.Value); expectedName != aux.Name {
		return fmt.Errorf("mismatched cipher suite and name, suite: %d, name: %s, expected name: %s", aux.Value, aux.Name, expectedName)
	}
	*cs = CipherSuite(aux.Value)
	return nil
}

type CompressionMethod uint8

func (cm *CompressionMethod) MarshalJSON() ([]byte, error) {
	buf := make([]byte, 1)
	buf[0] = byte(*cm)
	enc := strings.ToUpper(hex.EncodeToString(buf))
	aux := struct {
		Hex   string `json:"hex"`
		Name  string `json:"name"`
		Value uint8  `json:"value"`
	}{
		Hex:   fmt.Sprintf("0x%s", enc),
		Name:  cm.String(),
		Value: uint8(*cm),
	}

	return json.Marshal(aux)
}

func (cm *CompressionMethod) UnmarshalJSON(b []byte) error {
	aux := struct {
		Hex   string `json:"hex"`
		Name  string `json:"name"`
		Value uint8  `json:"value"`
	}{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	if expectedName := nameForCompressionMethod(aux.Value); expectedName != aux.Name {
		return fmt.Errorf("mismatched compression method and name, compression method: %d, name: %s, expected name: %s", aux.Value, aux.Name, expectedName)
	}
	*cm = CompressionMethod(aux.Value)
	return nil
}

func (c *Conn) GetHandshakeLog() *ServerHandshake {
	return c.handshakeLog
}

func (c *Conn) InCipher() (cipher interface{}) {
	return c.in.cipher
}

func (c *Conn) InSeq() []byte {
	return c.in.seq[:]
}

func (c *Conn) OutCipher() (cipher interface{}) {
	return c.out.cipher
}

func (c *Conn) OutSeq() []byte {
	return c.out.seq[:]
}

func (m *clientHelloMsg) MakeLog() *ClientHello {
	ch := new(ClientHello)

	ch.Version = TLSVersion(m.vers)

	ch.Random = make([]byte, len(m.random))
	copy(ch.Random, m.random)

	ch.SessionID = make([]byte, len(m.sessionId))
	copy(ch.SessionID, m.sessionId)

	ch.CipherSuites = make([]CipherSuite, len(m.cipherSuites))
	for i, aCipher := range m.cipherSuites {
		ch.CipherSuites[i] = CipherSuite(aCipher)
	}

	ch.CompressionMethods = make([]CompressionMethod, len(m.compressionMethods))
	for i, aCompressMethod := range m.compressionMethods {
		ch.CompressionMethods[i] = CompressionMethod(aCompressMethod)
	}

	ch.OcspStapling = m.ocspStapling
	ch.TicketSupported = m.ticketSupported
	ch.SecureRenegotiation = m.secureRenegotiation
	ch.HeartbeatSupported = m.heartbeatEnabled

	if len(m.extendedRandom) > 0 {
		ch.ExtendedRandom = make([]byte, len(m.extendedRandom))
		copy(ch.ExtendedRandom, m.extendedRandom)
	}

	ch.NextProtoNeg = m.nextProtoNeg
	ch.ServerName = m.serverName
	ch.Scts = m.scts

	ch.SupportedCurves = make([]CurveID, len(m.supportedCurves))
	copy(ch.SupportedCurves, m.supportedCurves)

	ch.SupportedPoints = make([]PointFormat, len(m.supportedPoints))
	for i, aFormat := range m.supportedPoints {
		ch.SupportedPoints[i] = PointFormat(aFormat)
	}

	if len(m.sessionTicket) > 0 {
		ch.SessionTicket = new(SessionTicket)
		copy(ch.SessionTicket.Value, m.sessionTicket)
		ch.SessionTicket.Length = len(m.sessionTicket)
		ch.SessionTicket.LifetimeHint = 0 // Clients don't send
	}

	ch.SignatureAndHashes = make([]SignatureAndHash, len(m.signatureAndHashes))
	for i, aGroup := range m.signatureAndHashes {
		ch.SignatureAndHashes[i] = SignatureAndHash(aGroup)
	}

	ch.SctEnabled = m.sctEnabled

	ch.AlpnProtocols = make([]string, len(m.alpnProtocols))
	copy(ch.AlpnProtocols, m.alpnProtocols)

	ch.UnknownExtensions = make([][]byte, len(m.unknownExtensions))
	for i, extBytes := range m.unknownExtensions {
		tempBytes := make([]byte, len(extBytes))
		copy(tempBytes, extBytes)
		ch.UnknownExtensions[i] = tempBytes
	}
	return ch
}

func (m *serverHelloMsg) MakeLog() *ServerHello {
	sh := new(ServerHello)
	sh.Version = TLSVersion(m.vers)
	sh.Random = make([]byte, len(m.random))
	copy(sh.Random, m.random)
	sh.SessionID = make([]byte, len(m.sessionId))
	copy(sh.SessionID, m.sessionId)
	sh.CipherSuite = CipherSuite(m.cipherSuite)
	sh.CompressionMethod = m.compressionMethod
	sh.OcspStapling = m.ocspStapling
	sh.TicketSupported = m.ticketSupported
	sh.SecureRenegotiation = m.secureRenegotiation
	sh.HeartbeatSupported = m.heartbeatEnabled
	if len(m.extendedRandom) > 0 {
		sh.ExtendedRandom = make([]byte, len(m.extendedRandom))
		copy(sh.ExtendedRandom, m.extendedRandom)
	}
	if len(m.scts) > 0 {
		for _, rawSCT := range m.scts {
			var out ParsedAndRawSCT
			out.Raw = make([]byte, len(rawSCT))
			copy(out.Raw, rawSCT)
			sct, err := ct.DeserializeSCT(bytes.NewReader(rawSCT))
			if err == nil {
				out.Parsed = sct
			}
			sh.SignedCertificateTimestamps = append(sh.SignedCertificateTimestamps, out)
		}
	}
	sh.ExtendedMasterSecret = m.extendedMasterSecret
	sh.AlpnProtocol = m.alpnProtocol
	return sh
}

func (m *certificateMsg) MakeLog() *Certificates {
	sc := new(Certificates)
	if len(m.certificates) >= 1 {
		cert := m.certificates[0]
		sc.Certificate.Raw = make([]byte, len(cert))
		copy(sc.Certificate.Raw, cert)
	}
	if len(m.certificates) >= 2 {
		chain := m.certificates[1:]
		sc.Chain = make([]SimpleCertificate, len(chain))
		for idx, cert := range chain {
			sc.Chain[idx].Raw = make([]byte, len(cert))
			copy(sc.Chain[idx].Raw, cert)
		}
	}
	return sc
}

// addParsed sets the parsed certificates and the validation. It assumes the
// chain slice has already been allocated.
func (c *Certificates) addParsed(certs []*x509.Certificate, validation *x509.Validation) {
	if len(certs) >= 1 {
		c.Certificate.Parsed = certs[0]
	}
	if len(certs) >= 2 {
		chain := certs[1:]
		for idx, cert := range chain {
			c.Chain[idx].Parsed = cert
		}
	}
	c.Validation = validation
}

func (m *serverKeyExchangeMsg) MakeLog(ka keyAgreement) *ServerKeyExchange {
	skx := new(ServerKeyExchange)
	skx.Raw = make([]byte, len(m.key))
	var auth keyAgreementAuthentication
	var errAuth error
	copy(skx.Raw, m.key)
	skx.Digest = append(make([]byte, 0), m.digest...)

	// Write out parameters
	switch ka := ka.(type) {
	case *rsaKeyAgreement:
		skx.RSAParams = ka.RSAParams()
		auth = ka.auth
		errAuth = ka.verifyError
	case *dheKeyAgreement:
		skx.DHParams = ka.DHParams()
		auth = ka.auth
		errAuth = ka.verifyError
	case *ecdheKeyAgreement:
		skx.ECDHParams = ka.ECDHParams()
		auth = ka.auth
		errAuth = ka.verifyError
	default:
		break
	}

	// Write out signature
	switch auth := auth.(type) {
	case *signedKeyAgreement:
		skx.Signature = auth.Signature()
	default:
		break
	}

	// Write the signature validation error
	if errAuth != nil {
		skx.SignatureError = errAuth.Error()
	}

	return skx
}

func (m *finishedMsg) MakeLog() *Finished {
	sf := new(Finished)
	sf.VerifyData = make([]byte, len(m.verifyData))
	copy(sf.VerifyData, m.verifyData)
	return sf
}

func (m *ClientSessionState) MakeLog() *SessionTicket {
	st := new(SessionTicket)
	st.Length = len(m.sessionTicket)
	st.Value = make([]uint8, st.Length)
	copy(st.Value, m.sessionTicket)
	st.LifetimeHint = m.lifetimeHint
	return st
}

func (m *clientHandshakeState) MakeLog() *KeyMaterial {
	keymat := new(KeyMaterial)

	keymat.MasterSecret = new(MasterSecret)
	keymat.MasterSecret.Length = len(m.masterSecret)
	keymat.MasterSecret.Value = make([]byte, len(m.masterSecret))
	copy(keymat.MasterSecret.Value, m.masterSecret)

	keymat.PreMasterSecret = new(PreMasterSecret)
	keymat.PreMasterSecret.Length = len(m.preMasterSecret)
	keymat.PreMasterSecret.Value = make([]byte, len(m.preMasterSecret))
	copy(keymat.PreMasterSecret.Value, m.preMasterSecret)

	return keymat
}

func (m *serverHandshakeState) MakeLog() *KeyMaterial {
	keymat := new(KeyMaterial)

	keymat.MasterSecret = new(MasterSecret)
	keymat.MasterSecret.Length = len(m.masterSecret)
	keymat.MasterSecret.Value = make([]byte, len(m.masterSecret))
	copy(keymat.MasterSecret.Value, m.masterSecret)

	keymat.PreMasterSecret = new(PreMasterSecret)
	keymat.PreMasterSecret.Length = len(m.preMasterSecret)
	keymat.PreMasterSecret.Value = make([]byte, len(m.preMasterSecret))
	copy(keymat.PreMasterSecret.Value, m.preMasterSecret)

	return keymat
}

func (m *clientKeyExchangeMsg) MakeLog(ka keyAgreement) *ClientKeyExchange {
	ckx := new(ClientKeyExchange)
	ckx.Raw = make([]byte, len(m.raw))
	copy(ckx.Raw, m.raw)

	switch ka := ka.(type) {
	case *rsaKeyAgreement:
		ckx.RSAParams = new(jsonKeys.RSAClientParams)
		ckx.RSAParams.Length = uint16(len(m.ciphertext) - 2) // First 2 bytes are length
		ckx.RSAParams.EncryptedPMS = make([]byte, len(m.ciphertext)-2)
		copy(ckx.RSAParams.EncryptedPMS, m.ciphertext[2:])
		// Premaster-Secret is available in KeyMaterial record
	case *dheKeyAgreement:
		ckx.DHParams = ka.ClientDHParams()
	case *ecdheKeyAgreement:
		ckx.ECDHParams = ka.ClientECDHParams()
	default:
		break
	}

	return ckx
}
