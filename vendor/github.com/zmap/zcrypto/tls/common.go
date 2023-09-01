// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"container/list"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/zmap/zcrypto/x509"
)

const (
	VersionSSL30 = 0x0300
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
)

const (
	maxPlaintext        = 16384        // maximum plaintext payload length
	maxCiphertext       = 16384 + 2048 // maximum ciphertext payload length
	tlsRecordHeaderLen  = 5            // record header length
	dtlsRecordHeaderLen = 13
	maxHandshake        = 65536 // maximum handshake we support (protocol max is 16 MB)

	minVersion = VersionSSL30
	maxVersion = VersionTLS12
)

// TLS record types.
type recordType uint8

const (
	recordTypeChangeCipherSpec recordType = 20
	recordTypeAlert            recordType = 21
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
)

// TLS handshake message types.
const (
	typeHelloRequest        uint8 = 0
	typeClientHello         uint8 = 1
	typeServerHello         uint8 = 2
	typeHelloVerifyRequest  uint8 = 3
	typeNewSessionTicket    uint8 = 4
	typeCertificate         uint8 = 11
	typeServerKeyExchange   uint8 = 12
	typeCertificateRequest  uint8 = 13
	typeServerHelloDone     uint8 = 14
	typeCertificateVerify   uint8 = 15
	typeClientKeyExchange   uint8 = 16
	typeFinished            uint8 = 20
	typeCertificateStatus   uint8 = 22
	typeNextProtocol        uint8 = 67  // Not IANA assigned
	typeEncryptedExtensions uint8 = 203 // Not IANA assigned
)

// TLS compression types.
const (
	compressionNone uint8 = 0
)

// TLS extension numbers
const (
	extensionServerName           uint16 = 0
	extensionStatusRequest        uint16 = 5
	extensionSupportedCurves      uint16 = 10
	extensionSupportedPoints      uint16 = 11
	extensionSignatureAlgorithms  uint16 = 13
	extensionALPN                 uint16 = 16
	extensionExtendedMasterSecret uint16 = 23
	extensionSessionTicket        uint16 = 35
	extensionNextProtoNeg         uint16 = 13172 // not IANA assigned
	extensionRenegotiationInfo    uint16 = 0xff01
	extensionExtendedRandom       uint16 = 0x0028 // not IANA assigned
	extensionSCT                  uint16 = 18
)

// TLS signaling cipher suite values
const (
	scsvRenegotiation uint16 = 0x00ff
)

// CurveID is the type of a TLS identifier for an elliptic curve. See
// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
type CurveID uint16

const (
	CurveP256 CurveID = 23
	CurveP384 CurveID = 24
	CurveP521 CurveID = 25
)

func (curveID *CurveID) MarshalJSON() ([]byte, error) {
	buf := make([]byte, 2)
	buf[0] = byte(*curveID >> 8)
	buf[1] = byte(*curveID)
	enc := strings.ToUpper(hex.EncodeToString(buf))
	aux := struct {
		Hex   string `json:"hex"`
		Name  string `json:"name"`
		Value uint16 `json:"value"`
	}{
		Hex:   fmt.Sprintf("0x%s", enc),
		Name:  curveID.String(),
		Value: uint16(*curveID),
	}

	return json.Marshal(aux)
}

func (curveID *CurveID) UnmarshalJSON(b []byte) error {
	aux := struct {
		Hex   string `json:"hex"`
		Name  string `json:"name"`
		Value uint16 `json:"value"`
	}{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	if expectedName := nameForCurve(aux.Value); expectedName != aux.Name {
		return fmt.Errorf("mismatched curve and name, curve: %d, name: %s, expected name: %s", aux.Value, aux.Name, expectedName)
	}
	*curveID = CurveID(aux.Value)
	return nil
}

type PointFormat uint8

// TLS Elliptic Curve Point Formats
// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-9
const (
	pointFormatUncompressed uint8 = 0
)

func (pFormat *PointFormat) MarshalJSON() ([]byte, error) {
	buf := make([]byte, 1)
	buf[0] = byte(*pFormat)
	enc := strings.ToUpper(hex.EncodeToString(buf))
	aux := struct {
		Hex   string `json:"hex"`
		Name  string `json:"name"`
		Value uint8  `json:"value"`
	}{
		Hex:   fmt.Sprintf("0x%s", enc),
		Name:  pFormat.String(),
		Value: uint8(*pFormat),
	}

	return json.Marshal(aux)
}

func (pFormat *PointFormat) UnmarshalJSON(b []byte) error {
	aux := struct {
		Hex   string `json:"hex"`
		Name  string `json:"name"`
		Value uint8  `json:"value"`
	}{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	if expectedName := nameForPointFormat(aux.Value); expectedName != aux.Name {
		return fmt.Errorf("mismatched point format and name, point format: %d, name: %s, expected name: %s", aux.Value, aux.Name, expectedName)
	}
	*pFormat = PointFormat(aux.Value)
	return nil
}

// TLS CertificateStatusType (RFC 3546)
const (
	statusTypeOCSP uint8 = 1
)

// Certificate types (for certificateRequestMsg)
const (
	certTypeRSASign    = 1 // A certificate containing an RSA key
	certTypeDSSSign    = 2 // A certificate containing a DSA key
	certTypeRSAFixedDH = 3 // A certificate containing a static DH key
	certTypeDSSFixedDH = 4 // A certificate containing a static DH key

	// See RFC4492 sections 3 and 5.5.
	certTypeECDSASign      = 64 // A certificate containing an ECDSA-capable public key, signed with ECDSA.
	certTypeRSAFixedECDH   = 65 // A certificate containing an ECDH-capable public key, signed with RSA.
	certTypeECDSAFixedECDH = 66 // A certificate containing an ECDH-capable public key, signed with ECDSA.

	// Rest of these are reserved by the TLS spec
)

// Hash functions for TLS 1.2 (See RFC 5246, section A.4.1)
const (
	hashMD5    uint8 = 1
	hashSHA1   uint8 = 2
	hashSHA224 uint8 = 3
	hashSHA256 uint8 = 4
	hashSHA384 uint8 = 5
	hashSHA512 uint8 = 6
)

// Signature algorithms for TLS 1.2 (See RFC 5246, section A.4.1)
const (
	signatureRSA   uint8 = 1
	signatureDSA   uint8 = 2
	signatureECDSA uint8 = 3
)

// SigAndHash mirrors the TLS 1.2, SignatureAndHashAlgorithm struct. See
// RFC 5246, section A.4.1.
type SigAndHash struct {
	Signature, Hash uint8
}

// supportedSKXSignatureAlgorithms contains the signature and hash algorithms
// that the code advertises as supported in a TLS 1.2 ClientHello.
var supportedSKXSignatureAlgorithms = []SigAndHash{
	{signatureRSA, hashSHA512},
	{signatureECDSA, hashSHA512},
	{signatureDSA, hashSHA512},
	{signatureRSA, hashSHA384},
	{signatureECDSA, hashSHA384},
	{signatureDSA, hashSHA384},
	{signatureRSA, hashSHA256},
	{signatureECDSA, hashSHA256},
	{signatureDSA, hashSHA256},
	{signatureRSA, hashSHA224},
	{signatureECDSA, hashSHA224},
	{signatureDSA, hashSHA224},
	{signatureRSA, hashSHA1},
	{signatureECDSA, hashSHA1},
	{signatureDSA, hashSHA1},
	{signatureRSA, hashMD5},
	{signatureECDSA, hashMD5},
	{signatureDSA, hashMD5},
}

var defaultSKXSignatureAlgorithms = []SigAndHash{
	{signatureRSA, hashSHA256},
	{signatureECDSA, hashSHA256},
	{signatureRSA, hashSHA1},
	{signatureECDSA, hashSHA1},
	{signatureRSA, hashSHA256},
	{signatureRSA, hashSHA384},
	{signatureRSA, hashSHA512},
}

// supportedClientCertSignatureAlgorithms contains the signature and hash
// algorithms that the code advertises as supported in a TLS 1.2
// CertificateRequest.
var supportedClientCertSignatureAlgorithms = []SigAndHash{
	{signatureRSA, hashSHA256},
	{signatureECDSA, hashSHA256},
}

// ConnectionState records basic TLS details about the connection.
type ConnectionState struct {
	Version                    uint16                  // TLS version used by the connection (e.g. VersionTLS12)
	HandshakeComplete          bool                    // TLS handshake is complete
	DidResume                  bool                    // connection resumes a previous TLS connection
	CipherSuite                uint16                  // cipher suite in use (TLS_RSA_WITH_RC4_128_SHA, ...)
	NegotiatedProtocol         string                  // negotiated next protocol (from Config.NextProtos)
	NegotiatedProtocolIsMutual bool                    // negotiated protocol was advertised by server
	ServerName                 string                  // server name requested by client, if any (server side only)
	PeerCertificates           []*x509.Certificate     // certificate chain presented by remote peer
	VerifiedChains             []x509.CertificateChain // verified chains built from PeerCertificates
}

// ClientAuthType declares the policy the server will follow for
// TLS Client Authentication.
type ClientAuthType int

const (
	// Values have no meaning (were previously 'iota')
	// Values added IOT allow dereference to name for JSON
	NoClientCert               ClientAuthType = 0
	RequestClientCert          ClientAuthType = 1
	RequireAnyClientCert       ClientAuthType = 2
	VerifyClientCertIfGiven    ClientAuthType = 3
	RequireAndVerifyClientCert ClientAuthType = 4
)

func (authType *ClientAuthType) String() string {
	if name, ok := clientAuthTypeNames[int(*authType)]; ok {
		return name
	}

	return "unknown"
}

func (authType *ClientAuthType) MarshalJSON() ([]byte, error) {
	return []byte(`"` + authType.String() + `"`), nil
}

func (authType *ClientAuthType) UnmarshalJSON(b []byte) error {
	panic("unimplemented")
}

// ClientSessionState contains the state needed by clients to resume TLS
// sessions.
type ClientSessionState struct {
	sessionTicket        []uint8             // Encrypted ticket used for session resumption with server
	lifetimeHint         uint32              // Hint from server about how long the session ticket should be stored
	vers                 uint16              // SSL/TLS version negotiated for the session
	cipherSuite          uint16              // Ciphersuite negotiated for the session
	masterSecret         []byte              // MasterSecret generated by client on a full handshake
	serverCertificates   []*x509.Certificate // Certificate chain presented by the server
	extendedMasterSecret bool                // Whether an extended master secret was used to generate the session
}

// ClientSessionCache is a cache of ClientSessionState objects that can be used
// by a client to resume a TLS session with a given server. ClientSessionCache
// implementations should expect to be called concurrently from different
// goroutines.
type ClientSessionCache interface {
	// Get searches for a ClientSessionState associated with the given key.
	// On return, ok is true if one was found.
	Get(sessionKey string) (session *ClientSessionState, ok bool)

	// Put adds the ClientSessionState to the cache with the given key.
	Put(sessionKey string, cs *ClientSessionState)
}

// A Config structure is used to configure a TLS client or server.
// After one has been passed to a TLS function it must not be
// modified. A Config may be reused; the tls package will also not
// modify it.
type Config struct {
	// Rand provides the source of entropy for nonces and RSA blinding.
	// If Rand is nil, TLS uses the cryptographic random reader in package
	// crypto/rand.
	// The Reader must be safe for use by multiple goroutines.
	Rand io.Reader

	// Time returns the current time as the number of seconds since the epoch.
	// If Time is nil, TLS uses time.Now.
	Time func() time.Time

	// Certificates contains one or more certificate chains
	// to present to the other side of the connection.
	// Server configurations must include at least one certificate.
	Certificates []Certificate

	// NameToCertificate maps from a certificate name to an element of
	// Certificates. Note that a certificate name can be of the form
	// '*.example.com' and so doesn't have to be a domain name as such.
	// See Config.BuildNameToCertificate
	// The nil value causes the first element of Certificates to be used
	// for all connections.
	NameToCertificate map[string]*Certificate

	// RootCAs defines the set of root certificate authorities
	// that clients use when verifying server certificates.
	// If RootCAs is nil, TLS uses the host's root CA set.
	RootCAs *x509.CertPool

	// NextProtos is a list of supported, application level protocols.
	NextProtos []string

	// ServerName is used to verify the hostname on the returned
	// certificates unless InsecureSkipVerify is given. It is also included
	// in the client's handshake to support virtual hosting.
	ServerName string

	// ClientAuth determines the server's policy for
	// TLS Client Authentication. The default is NoClientCert.
	ClientAuth ClientAuthType

	// ClientCAs defines the set of root certificate authorities
	// that servers use if required to verify a client certificate
	// by the policy in ClientAuth.
	ClientCAs *x509.CertPool

	// InsecureSkipVerify controls whether a client verifies the
	// server's certificate chain and host name.
	// If InsecureSkipVerify is true, TLS accepts any certificate
	// presented by the server and any host name in that certificate.
	// In this mode, TLS is susceptible to man-in-the-middle attacks.
	// This should be used only for testing.
	InsecureSkipVerify bool

	// CipherSuites is a list of supported cipher suites. If CipherSuites
	// is nil, TLS uses a list of suites supported by the implementation.
	CipherSuites []uint16

	// PreferServerCipherSuites controls whether the server selects the
	// client's most preferred ciphersuite, or the server's most preferred
	// ciphersuite. If true then the server's preference, as expressed in
	// the order of elements in CipherSuites, is used.
	PreferServerCipherSuites bool

	// SessionTicketsDisabled may be set to true to disable session ticket
	// (resumption) support.
	SessionTicketsDisabled bool

	// SessionTicketKey is used by TLS servers to provide session
	// resumption. See RFC 5077. If zero, it will be filled with
	// random data before the first server handshake.
	//
	// If multiple servers are terminating connections for the same host
	// they should all have the same SessionTicketKey. If the
	// SessionTicketKey leaks, previously recorded and future TLS
	// connections using that key are compromised.
	SessionTicketKey [32]byte

	// SessionCache is a cache of ClientSessionState entries for TLS session
	// resumption.
	ClientSessionCache ClientSessionCache

	// MinVersion contains the minimum SSL/TLS version that is acceptable.
	// If zero, then SSLv3 is taken as the minimum.
	MinVersion uint16

	// MaxVersion contains the maximum SSL/TLS version that is acceptable.
	// If zero, then the maximum version supported by this package is used,
	// which is currently TLS 1.2.
	MaxVersion uint16

	// CurvePreferences contains the elliptic curves that will be used in
	// an ECDHE handshake, in preference order. If empty, the default will
	// be used.
	CurvePreferences []CurveID

	// If enabled, empty CurvePreferences indicates that there are no curves
	// supported for ECDHE key exchanges
	ExplicitCurvePreferences bool

	// If enabled, specifies the signature and hash algorithms to be accepted by
	// a server, or sent by a client
	SignatureAndHashes []SigAndHash

	serverInitOnce sync.Once // guards calling (*Config).serverInit

	// Add all ciphers in CipherSuites to Client Hello even if unimplemented
	// Client-side Only
	ForceSuites bool

	// Export RSA Key
	ExportRSAKey *rsa.PrivateKey

	// HeartbeatEnabled sets whether the heartbeat extension is sent
	HeartbeatEnabled bool

	// ClientDSAEnabled sets whether a TLS client will accept server DSA keys
	// and DSS signatures
	ClientDSAEnabled bool

	// Use extended random
	ExtendedRandom bool

	// Force Client Hello to send TLS Session Ticket extension
	ForceSessionTicketExt bool

	// Enable use of the Extended Master Secret extension
	ExtendedMasterSecret bool

	SignedCertificateTimestampExt bool

	// Explicitly set Client random
	ClientRandom []byte

	// Explicitly set ClientHello with raw data
	ExternalClientHello []byte

	// If non-null specifies the contents of the client-hello
	// WARNING: Setting this may invalidate other fields in the Config object
	ClientFingerprintConfiguration *ClientFingerprintConfiguration

	// GetConfigForClient, if not nil, is called after a ClientHello is
	// received from a client. It may return a non-nil Config in order to
	// change the Config that will be used to handle this connection. If
	// the returned Config is nil, the original Config will be used. The
	// Config returned by this callback may not be subsequently modified.
	//
	// If GetConfigForClient is nil, the Config passed to Server() will be
	// used for all connections.
	//
	// Uniquely for the fields in the returned Config, session ticket keys
	// will be duplicated from the original Config if not set.
	// Specifically, if SetSessionTicketKeys was called on the original
	// config but not on the returned config then the ticket keys from the
	// original config will be copied into the new config before use.
	// Otherwise, if SessionTicketKey was set in the original config but
	// not in the returned config then it will be copied into the returned
	// config before use. If neither of those cases applies then the key
	// material from the returned config will be used for session tickets.
	GetConfigForClient func(*ClientHelloInfo) (*Config, error)

	// CertsOnly is used to cause a client to close the TLS connection
	// as soon as the server's certificates have been received
	CertsOnly bool

	// DontBufferHandshakes causes Handshake() to act like older versions of the go crypto library, where each TLS packet is sent in a separate Write.
	DontBufferHandshakes bool

	// mutex protects sessionTicketKeys and originalConfig.
	mutex sync.RWMutex
	// sessionTicketKeys contains zero or more ticket keys. If the length
	// is zero, SessionTicketsDisabled must be true. The first key is used
	// for new tickets and any subsequent keys can be used to decrypt old
	// tickets.
	sessionTicketKeys []ticketKey
	// originalConfig is set to the Config that was passed to Server if
	// this Config is returned by a GetConfigForClient callback. It's used
	// by serverInit in order to copy session ticket keys if needed.
	originalConfig *Config
}

// ticketKeyNameLen is the number of bytes of identifier that is prepended to
// an encrypted session ticket in order to identify the key used to encrypt it.
const ticketKeyNameLen = 16

// ticketKey is the internal representation of a session ticket key.
type ticketKey struct {
	// keyName is an opaque byte string that serves to identify the session
	// ticket key. It's exposed as plaintext in every session ticket.
	keyName [ticketKeyNameLen]byte
	aesKey  [16]byte
	hmacKey [16]byte
}

// ticketKeyFromBytes converts from the external representation of a session
// ticket key to a ticketKey. Externally, session ticket keys are 32 random
// bytes and this function expands that into sufficient name and key material.
func ticketKeyFromBytes(b [32]byte) (key ticketKey) {
	hashed := sha512.Sum512(b[:])
	copy(key.keyName[:], hashed[:ticketKeyNameLen])
	copy(key.aesKey[:], hashed[ticketKeyNameLen:ticketKeyNameLen+16])
	copy(key.hmacKey[:], hashed[ticketKeyNameLen+16:ticketKeyNameLen+32])
	return key
}

// Clone returns a shallow clone of c. It is safe to clone a Config that is
// being used concurrently by a TLS client or server.
func (c *Config) Clone() *Config {
	// Running serverInit ensures that it's safe to read
	// SessionTicketsDisabled.
	c.serverInitOnce.Do(c.serverInit)

	var sessionTicketKeys []ticketKey
	c.mutex.RLock()
	sessionTicketKeys = c.sessionTicketKeys
	c.mutex.RUnlock()

	return &Config{
		Rand:                           c.Rand,
		Time:                           c.Time,
		Certificates:                   c.Certificates,
		NameToCertificate:              c.NameToCertificate,
		GetConfigForClient:             c.GetConfigForClient,
		RootCAs:                        c.RootCAs,
		NextProtos:                     c.NextProtos,
		ServerName:                     c.ServerName,
		ClientAuth:                     c.ClientAuth,
		ClientCAs:                      c.ClientCAs,
		InsecureSkipVerify:             c.InsecureSkipVerify,
		CipherSuites:                   c.CipherSuites,
		PreferServerCipherSuites:       c.PreferServerCipherSuites,
		SessionTicketsDisabled:         c.SessionTicketsDisabled,
		SessionTicketKey:               c.SessionTicketKey,
		ClientSessionCache:             c.ClientSessionCache,
		MinVersion:                     c.MinVersion,
		MaxVersion:                     c.MaxVersion,
		CurvePreferences:               c.CurvePreferences,
		ExplicitCurvePreferences:       c.ExplicitCurvePreferences,
		sessionTicketKeys:              sessionTicketKeys,
		ClientFingerprintConfiguration: c.ClientFingerprintConfiguration,
		CertsOnly:                      c.CertsOnly,
		// originalConfig is deliberately not duplicated.

		// Not merged from upstream:
		// GetCertificate: c.GetCertificate,
		// DynamicRecordSizingDisabled: c.DynamicRecordSizingDisabled,
		// VerifyPeerCertificate:    c.VerifyPeerCertificate,
		// KeyLogWriter:             c.KeyLogWriter,
		// Renegotiation:            c.Renegotiation,
	}
}

func (c *Config) serverInit() {
	if c.SessionTicketsDisabled || len(c.ticketKeys()) != 0 {
		return
	}

	var originalConfig *Config
	c.mutex.Lock()
	originalConfig, c.originalConfig = c.originalConfig, nil
	c.mutex.Unlock()

	alreadySet := false
	for _, b := range c.SessionTicketKey {
		if b != 0 {
			alreadySet = true
			break
		}
	}

	if !alreadySet {
		if originalConfig != nil {
			copy(c.SessionTicketKey[:], originalConfig.SessionTicketKey[:])
		} else if _, err := io.ReadFull(c.rand(), c.SessionTicketKey[:]); err != nil {
			c.SessionTicketsDisabled = true
			return
		}
	}

	if originalConfig != nil {
		originalConfig.mutex.RLock()
		c.sessionTicketKeys = originalConfig.sessionTicketKeys
		originalConfig.mutex.RUnlock()
	} else {
		c.sessionTicketKeys = []ticketKey{ticketKeyFromBytes(c.SessionTicketKey)}
	}
}

func (c *Config) ticketKeys() []ticketKey {
	c.mutex.RLock()
	// c.sessionTicketKeys is constant once created. SetSessionTicketKeys
	// will only update it by replacing it with a new value.
	ret := c.sessionTicketKeys
	c.mutex.RUnlock()
	return ret
}

func (c *Config) rand() io.Reader {
	r := c.Rand
	if r == nil {
		return rand.Reader
	}
	return r
}

func (c *Config) time() time.Time {
	t := c.Time
	if t == nil {
		t = time.Now
	}
	return t()
}

func (c *Config) cipherSuites() []uint16 {
	s := c.CipherSuites
	if s == nil {
		s = defaultCipherSuites()
	}
	return s
}

func (c *Config) minVersion() uint16 {
	if c == nil || c.MinVersion == 0 {
		return minVersion
	}
	return c.MinVersion
}

func (c *Config) maxVersion() uint16 {
	if c == nil || c.MaxVersion == 0 {
		return maxVersion
	}
	return c.MaxVersion
}

var defaultCurvePreferences = []CurveID{CurveP256, CurveP384, CurveP521}

func (c *Config) curvePreferences() []CurveID {
	if c.ExplicitCurvePreferences {
		return c.CurvePreferences
	}
	if c == nil || len(c.CurvePreferences) == 0 {
		return defaultCurvePreferences
	}
	return c.CurvePreferences
}

// mutualVersion returns the protocol version to use given the advertised
// version of the peer.
func (c *Config) mutualVersion(vers uint16) (uint16, bool) {
	minVersion := c.minVersion()
	maxVersion := c.maxVersion()

	if vers < minVersion {
		return 0, false
	}
	if vers > maxVersion {
		vers = maxVersion
	}
	return vers, true
}

// SetSessionTicketKeys updates the session ticket keys for a server. The first
// key will be used when creating new tickets, while all keys can be used for
// decrypting tickets. It is safe to call this function while the server is
// running in order to rotate the session ticket keys. The function will panic
// if keys is empty.
func (c *Config) SetSessionTicketKeys(keys [][32]byte) {
	if len(keys) == 0 {
		panic("tls: keys must have at least one key")
	}

	newKeys := make([]ticketKey, len(keys))
	for i, bytes := range keys {
		newKeys[i] = ticketKeyFromBytes(bytes)
	}

	c.mutex.Lock()
	c.sessionTicketKeys = newKeys
	c.mutex.Unlock()
}

// getCertificateForName returns the best certificate for the given name,
// defaulting to the first element of c.Certificates if there are no good
// options.
func (c *Config) getCertificateForName(name string) *Certificate {
	if len(c.Certificates) == 1 || c.NameToCertificate == nil {
		// There's only one choice, so no point doing any work.
		return &c.Certificates[0]
	}

	name = strings.ToLower(name)
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}

	if cert, ok := c.NameToCertificate[name]; ok {
		return cert
	}

	// try replacing labels in the name with wildcards until we get a
	// match.
	labels := strings.Split(name, ".")
	for i := range labels {
		labels[i] = "*"
		candidate := strings.Join(labels, ".")
		if cert, ok := c.NameToCertificate[candidate]; ok {
			return cert
		}
	}

	// If nothing matches, return the first certificate.
	return &c.Certificates[0]
}

func (c *Config) signatureAndHashesForServer() []SigAndHash {
	if c != nil && c.SignatureAndHashes != nil {
		return c.SignatureAndHashes
	}
	return supportedClientCertSignatureAlgorithms
}

func (c *Config) signatureAndHashesForClient() []SigAndHash {
	if c != nil && c.SignatureAndHashes != nil {
		return c.SignatureAndHashes
	}
	if c.ClientDSAEnabled {
		return supportedSKXSignatureAlgorithms
	}
	return defaultSKXSignatureAlgorithms
}

// BuildNameToCertificate parses c.Certificates and builds c.NameToCertificate
// from the CommonName and SubjectAlternateName fields of each of the leaf
// certificates.
func (c *Config) BuildNameToCertificate() {
	c.NameToCertificate = make(map[string]*Certificate)
	for i := range c.Certificates {
		cert := &c.Certificates[i]
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			continue
		}
		if len(x509Cert.Subject.CommonName) > 0 {
			c.NameToCertificate[x509Cert.Subject.CommonName] = cert
		}
		for _, san := range x509Cert.DNSNames {
			c.NameToCertificate[san] = cert
		}
	}
}

// A Certificate is a chain of one or more certificates, leaf first.
type Certificate struct {
	Certificate [][]byte `json:"certificate_chain,omitempty"`

	// supported types: *rsa.PrivateKey, *ecdsa.PrivateKey
	// OCSPStaple contains an optional OCSP response which will be served
	// to clients that request it.
	// Don't expose the private key by default (can be marshalled manually)
	PrivateKey crypto.PrivateKey `json:"-"`

	OCSPStaple []byte `json:"ocsp_staple,omitempty"`

	// Leaf is the parsed form of the leaf certificate, which may be
	// initialized using x509.ParseCertificate to reduce per-handshake
	// processing for TLS clients doing client authentication. If nil, the
	// leaf certificate will be parsed as needed.
	Leaf *x509.Certificate `json:"leaf,omitempty"`
}

// A TLS record.
type record struct {
	contentType  recordType
	major, minor uint8
	payload      []byte
}

type handshakeMessage interface {
	marshal() []byte
	unmarshal([]byte) bool
}

// lruSessionCache is a ClientSessionCache implementation that uses an LRU
// caching strategy.
type lruSessionCache struct {
	sync.Mutex

	m        map[string]*list.Element
	q        *list.List
	capacity int
}

type lruSessionCacheEntry struct {
	sessionKey string
	state      *ClientSessionState
}

// NewLRUClientSessionCache returns a ClientSessionCache with the given
// capacity that uses an LRU strategy. If capacity is < 1, a default capacity
// is used instead.
func NewLRUClientSessionCache(capacity int) ClientSessionCache {
	const defaultSessionCacheCapacity = 64

	if capacity < 1 {
		capacity = defaultSessionCacheCapacity
	}
	return &lruSessionCache{
		m:        make(map[string]*list.Element),
		q:        list.New(),
		capacity: capacity,
	}
}

// Put adds the provided (sessionKey, cs) pair to the cache.
func (c *lruSessionCache) Put(sessionKey string, cs *ClientSessionState) {
	c.Lock()
	defer c.Unlock()

	if elem, ok := c.m[sessionKey]; ok {
		entry := elem.Value.(*lruSessionCacheEntry)
		entry.state = cs
		c.q.MoveToFront(elem)
		return
	}

	if c.q.Len() < c.capacity {
		entry := &lruSessionCacheEntry{sessionKey, cs}
		c.m[sessionKey] = c.q.PushFront(entry)
		return
	}

	elem := c.q.Back()
	entry := elem.Value.(*lruSessionCacheEntry)
	delete(c.m, entry.sessionKey)
	entry.sessionKey = sessionKey
	entry.state = cs
	c.q.MoveToFront(elem)
	c.m[sessionKey] = elem
}

// Get returns the ClientSessionState value associated with a given key. It
// returns (nil, false) if no value is found.
func (c *lruSessionCache) Get(sessionKey string) (*ClientSessionState, bool) {
	c.Lock()
	defer c.Unlock()

	if elem, ok := c.m[sessionKey]; ok {
		c.q.MoveToFront(elem)
		return elem.Value.(*lruSessionCacheEntry).state, true
	}
	return nil, false
}

// TODO(jsing): Make these available to both crypto/x509 and crypto/tls.
type dsaSignature struct {
	R, S *big.Int
}

type ecdsaSignature dsaSignature

var emptyConfig Config = Config{InsecureSkipVerify: true}

func defaultConfig() *Config {
	return &emptyConfig
}

var (
	once                   sync.Once
	varDefaultCipherSuites []uint16
)

func defaultCipherSuites() []uint16 {
	once.Do(initDefaultCipherSuites)
	return varDefaultCipherSuites
}

func initDefaultCipherSuites() {
	varDefaultCipherSuites = make([]uint16, len(stdlibCipherSuites))
	for i, suite := range stdlibCipherSuites {
		varDefaultCipherSuites[i] = suite.id
	}
}

func unexpectedMessageError(wanted, got interface{}) error {
	return fmt.Errorf("tls: received unexpected handshake message of type %T when waiting for %T", got, wanted)
}

func isSupportedSignatureAndHash(sigHash SigAndHash, sigHashes []SigAndHash) bool {
	for _, s := range sigHashes {
		if s == sigHash {
			return true
		}
	}
	return false
}

// SignatureScheme identifies a signature algorithm supported by TLS. See
// https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.2.3.
type SignatureScheme uint16

const (
	PKCS1WithSHA1   SignatureScheme = 0x0201
	PKCS1WithSHA256 SignatureScheme = 0x0401
	PKCS1WithSHA384 SignatureScheme = 0x0501
	PKCS1WithSHA512 SignatureScheme = 0x0601

	PSSWithSHA256 SignatureScheme = 0x0804
	PSSWithSHA384 SignatureScheme = 0x0805
	PSSWithSHA512 SignatureScheme = 0x0806

	ECDSAWithP256AndSHA256 SignatureScheme = 0x0403
	ECDSAWithP384AndSHA384 SignatureScheme = 0x0503
	ECDSAWithP521AndSHA512 SignatureScheme = 0x0603

	EdDSAWithEd25519 SignatureScheme = 0x0807
	EdDSAWithEd448   SignatureScheme = 0x0808
)

func (sigScheme *SignatureScheme) MarshalJSON() ([]byte, error) {
	buf := sigScheme.Bytes()
	enc := strings.ToUpper(hex.EncodeToString(buf))
	aux := struct {
		Hex   string `json:"hex"`
		Name  string `json:"name"`
		Value uint16 `json:"value"`
	}{
		Hex:   fmt.Sprintf("0x%s", enc),
		Name:  sigScheme.String(),
		Value: uint16(*sigScheme),
	}

	return json.Marshal(aux)
}

func (sigScheme *SignatureScheme) UnmarshalJSON(b []byte) error {
	aux := struct {
		Hex   string `json:"hex"`
		Name  string `json:"name"`
		Value uint16 `json:"value"`
	}{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	if expectedName := nameForSignatureScheme(aux.Value); expectedName != aux.Name {
		return fmt.Errorf("mismatched signature scheme and name, signature scheme: %d, name: %s, expected name: %s", aux.Value, aux.Name, expectedName)
	}
	*sigScheme = SignatureScheme(aux.Value)
	return nil
}

// ClientHelloInfo contains information from a ClientHello message in order to
// guide certificate selection in the GetCertificate callback.
type ClientHelloInfo struct {
	// CipherSuites lists the CipherSuites supported by the client (e.g.
	// TLS_RSA_WITH_RC4_128_SHA).
	CipherSuites []uint16

	// ServerName indicates the name of the server requested by the client
	// in order to support virtual hosting. ServerName is only set if the
	// client is using SNI (see
	// http://tools.ietf.org/html/rfc4366#section-3.1).
	ServerName string

	// SupportedCurves lists the elliptic curves supported by the client.
	// SupportedCurves is set only if the Supported Elliptic Curves
	// Extension is being used (see
	// http://tools.ietf.org/html/rfc4492#section-5.1.1).
	SupportedCurves []CurveID

	// SupportedPoints lists the point formats supported by the client.
	// SupportedPoints is set only if the Supported Point Formats Extension
	// is being used (see
	// http://tools.ietf.org/html/rfc4492#section-5.1.2).
	SupportedPoints []uint8

	// SignatureSchemes lists the signature and hash schemes that the client
	// is willing to verify. SignatureSchemes is set only if the Signature
	// Algorithms Extension is being used (see
	// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1).
	SignatureSchemes []SignatureScheme

	// SupportedProtos lists the application protocols supported by the client.
	// SupportedProtos is set only if the Application-Layer Protocol
	// Negotiation Extension is being used (see
	// https://tools.ietf.org/html/rfc7301#section-3.1).
	//
	// Servers can select a protocol by setting Config.NextProtos in a
	// GetConfigForClient return value.
	SupportedProtos []string

	// SupportedVersions lists the TLS versions supported by the client.
	// For TLS versions less than 1.3, this is extrapolated from the max
	// version advertised by the client, so values other than the greatest
	// might be rejected if used.
	SupportedVersions []uint16

	// Conn is the underlying net.Conn for the connection. Do not read
	// from, or write to, this connection; that will cause the TLS
	// connection to fail.
	Conn net.Conn

	// Add a pointer to the entire tls handshake structure so that it can
	// be retrieved without hijacking the connection from higher-level
	// packages
	HandshakeLog *ServerHandshake
}

func (info *ClientHelloInfo) MarshalJSON() ([]byte, error) {
	aux := struct {
		CipherSuites      []CipherSuite     `json:"cipher_suites"`
		ServerName        string            `json:"server_name,omitempty"`
		SupportedCurves   []CurveID         `json:"supported_curves,omitempty"`
		SupportedPoints   []PointFormat     `json:"supported_point_formats,omitempty"`
		SignatureSchemes  []SignatureScheme `json:"signature_schemes,omitempty"`
		SupportedProtos   []string          `json:"supported_protocols,omitempty"`
		SupportedVersions []TLSVersion      `json:"supported_versions,omitempty"`
		LocalAddr         string            `json:"local_address,omitempty"`
		RemoteAddr        string            `json:"remote_address,omitempty"`
	}{
		ServerName:       info.ServerName,
		SupportedCurves:  info.SupportedCurves,
		SignatureSchemes: info.SignatureSchemes,
		SupportedProtos:  info.SupportedProtos,
		// Do not marshal HandshakeLog IOT avoid duplication of data
		// HandshakeLog can be marshalled manually from
		// ClientHelloInfo.HandshakeLog or Conn.GetHandshakeLog()
	}

	aux.CipherSuites = make([]CipherSuite, len(info.CipherSuites))
	for i, cipher := range info.CipherSuites {
		aux.CipherSuites[i] = CipherSuite(cipher)
	}

	aux.SupportedPoints = make([]PointFormat, len(info.SupportedPoints))
	for i, format := range info.SupportedPoints {
		aux.SupportedPoints[i] = PointFormat(format)
	}

	aux.SupportedVersions = make([]TLSVersion, len(info.SupportedVersions))
	for i, version := range info.SupportedVersions {
		aux.SupportedVersions[i] = TLSVersion(version)
	}

	aux.LocalAddr = fmt.Sprintf("%s+%s", info.Conn.LocalAddr().String(), info.Conn.LocalAddr().Network())
	aux.RemoteAddr = fmt.Sprintf("%s+%s", info.Conn.RemoteAddr().String(), info.Conn.RemoteAddr().Network())

	return json.Marshal(aux)
}

func (info *ClientHelloInfo) UnmarshalJSON(b []byte) error {
	aux := struct {
		CipherSuites      []CipherSuite     `json:"cipher_suites"`
		ServerName        string            `json:"server_name,omitempty"`
		SupportedCurves   []CurveID         `json:"supported_curves,omitempty"`
		SupportedPoints   []PointFormat     `json:"supported_point_formats,omitempty"`
		SignatureSchemes  []SignatureScheme `json:"signature_schemes,omitempty"`
		SupportedProtos   []string          `json:"supported_protocols,omitempty"`
		SupportedVersions []TLSVersion      `json:"supported_versions,omitempty"`
		LocalAddr         string            `json:"local_address,omitempty"`
		RemoteAddr        string            `json:"remote_address,omitempty"`
	}{}

	err := json.Unmarshal(b, &aux)
	if err != nil {
		return err
	}

	splitLocalAddr := strings.Split(aux.LocalAddr, "+")
	if len(splitLocalAddr) != 2 {
		return errors.New("local_address is not unmarshalable")
	}
	splitRemoteAddr := strings.Split(aux.RemoteAddr, "+")
	if len(splitRemoteAddr) != 2 {
		return errors.New("remote_address is not unmarshalable")
	}

	info.Conn = FakeConn{
		localAddr: FakeAddr{
			stringStr:  splitLocalAddr[0],
			networkStr: splitLocalAddr[1],
		},
		remoteAddr: FakeAddr{
			stringStr:  splitRemoteAddr[0],
			networkStr: splitLocalAddr[1],
		},
	}

	info.ServerName = aux.ServerName
	info.SupportedCurves = aux.SupportedCurves
	info.SignatureSchemes = aux.SignatureSchemes
	info.SupportedProtos = aux.SupportedProtos

	info.CipherSuites = make([]uint16, len(aux.CipherSuites))
	for i, cipher := range aux.CipherSuites {
		info.CipherSuites[i] = uint16(cipher)
	}

	info.SupportedPoints = make([]uint8, len(aux.SupportedPoints))
	for i, format := range aux.SupportedPoints {
		info.SupportedPoints[i] = uint8(format)
	}

	info.SupportedVersions = make([]uint16, len(aux.SupportedVersions))
	for i, version := range aux.SupportedVersions {
		info.SupportedVersions[i] = uint16(version)
	}

	return nil
}

// FakeConn and FakeAddr are to allow unmarshaling of tls objects that contain
// net.Conn objects
// With the exeption of recovering the net.Addr strings contained in the JSON,
// any attempt to use these objects will result in a runtime panic()
type FakeConn struct {
	localAddr  FakeAddr
	remoteAddr FakeAddr
}

func (fConn FakeConn) Read(b []byte) (int, error) {
	panic("Read() on FakeConn")
}

func (fConn FakeConn) Write(b []byte) (int, error) {
	panic("Write() on FakeConn")
}

func (fConn FakeConn) Close() error {
	panic("Close() on FakeConn")
}

func (fConn FakeConn) LocalAddr() net.Addr {
	return fConn.localAddr
}

func (fConn FakeConn) RemoteAddr() net.Addr {
	return fConn.remoteAddr
}

func (fConn FakeConn) SetDeadline(t time.Time) error {
	panic("SetDeadline() on FakeConn")
}

func (fConn FakeConn) SetReadDeadline(t time.Time) error {
	panic("SetReadDeadline() on FakeConn")
}

func (fConn FakeConn) SetWriteDeadline(t time.Time) error {
	panic("SetWriteDeadline() on FakeConn")
}

type FakeAddr struct {
	networkStr string
	stringStr  string
}

func (fAddr FakeAddr) String() string {
	return fAddr.stringStr
}

func (fAddr FakeAddr) Network() string {
	return fAddr.networkStr
}

type ConfigJSON struct {
	Certificates                   []Certificate                   `json:"certificates,omitempty"`
	RootCAs                        *x509.CertPool                  `json:"root_cas,omitempty"`
	NextProtos                     []string                        `json:"next_protocols,omitempty"`
	ServerName                     string                          `json:"server_name,omitempty"`
	ClientAuth                     ClientAuthType                  `json:"client_auth_type"`
	ClientCAs                      *x509.CertPool                  `json:"client_cas,omitempty"`
	InsecureSkipVerify             bool                            `json:"skip_verify"`
	CipherSuites                   []CipherSuite                   `json:"cipher_suites,omitempty"`
	PreferServerCipherSuites       bool                            `json:"prefer_server_cipher_suites"`
	SessionTicketsDisabled         bool                            `json:"session_tickets_disabled"`
	SessionTicketKey               []byte                          `json:"session_ticket_key,omitempty"`
	ClientSessionCache             ClientSessionCache              `json:"client_session_cache,omitempty"`
	MinVersion                     TLSVersion                      `json:"min_tls_version,omitempty"`
	MaxVersion                     TLSVersion                      `json:"max_tls_version,omitempty"`
	CurvePreferences               []CurveID                       `json:"curve_preferences,omitempty"`
	ExplicitCurvePreferences       bool                            `json:"explicit_curve_preferences"`
	ForceSuites                    bool                            `json:"force_cipher_suites"`
	ExportRSAKey                   *rsa.PrivateKey                 `json:"export_rsa_key,omitempty"`
	HeartbeatEnabled               bool                            `json:"heartbeat_enabled"`
	ClientDSAEnabled               bool                            `json:"client_dsa_enabled"`
	ExtendedRandom                 bool                            `json:"extended_random_enabled"`
	ForceSessionTicketExt          bool                            `json:"session_ticket_ext_enabled"`
	ExtendedMasterSecret           bool                            `json:"extended_master_secret_enabled"`
	SignedCertificateTimestampExt  bool                            `json:"sct_ext_enabled"`
	ClientRandom                   []byte                          `json:"client_random,omitempty"`
	ExternalClientHello            []byte                          `json:"external_client_hello,omitempty"`
	ClientFingerprintConfiguration *ClientFingerprintConfiguration `json:"client_fingerprint_config,omitempty"`
	DontBufferHandshakes           bool                            `json:"dont_buffer_handshakes"`
}

func (config *Config) MarshalJSON() ([]byte, error) {
	aux := new(ConfigJSON)

	aux.Certificates = config.Certificates
	aux.RootCAs = config.RootCAs
	aux.NextProtos = config.NextProtos
	aux.ServerName = config.ServerName
	aux.ClientAuth = config.ClientAuth
	aux.ClientCAs = config.ClientCAs
	aux.InsecureSkipVerify = config.InsecureSkipVerify

	ciphers := config.cipherSuites()
	aux.CipherSuites = make([]CipherSuite, len(ciphers))
	for i, aCipher := range ciphers {
		aux.CipherSuites[i] = CipherSuite(aCipher)
	}

	aux.PreferServerCipherSuites = config.PreferServerCipherSuites
	aux.SessionTicketsDisabled = config.SessionTicketsDisabled
	aux.SessionTicketKey = config.SessionTicketKey[:]
	aux.ClientSessionCache = config.ClientSessionCache
	aux.MinVersion = TLSVersion(config.minVersion())
	aux.MaxVersion = TLSVersion(config.maxVersion())
	aux.CurvePreferences = config.curvePreferences()
	aux.ExplicitCurvePreferences = config.ExplicitCurvePreferences
	aux.ForceSuites = config.ForceSuites
	aux.ExportRSAKey = config.ExportRSAKey
	aux.HeartbeatEnabled = config.HeartbeatEnabled
	aux.ClientDSAEnabled = config.ClientDSAEnabled
	aux.ExtendedRandom = config.ExtendedRandom
	aux.ForceSessionTicketExt = config.ForceSessionTicketExt
	aux.ExtendedMasterSecret = config.ExtendedMasterSecret
	aux.SignedCertificateTimestampExt = config.SignedCertificateTimestampExt
	aux.ClientRandom = config.ClientRandom
	aux.ExternalClientHello = config.ExternalClientHello
	aux.ClientFingerprintConfiguration = config.ClientFingerprintConfiguration
	aux.DontBufferHandshakes = config.DontBufferHandshakes

	return json.Marshal(aux)
}

func (config *Config) UnmarshalJSON(b []byte) error {
	panic("unimplemented")
}

// Error type raised by doFullHandshake() when the CertsOnly option is
// in use
var ErrCertsOnly = errors.New("handshake abandoned per CertsOnly option")
