// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/zmap/zcrypto/rsa"
	"github.com/zmap/zcrypto/x509"
)

type clientHandshakeState struct {
	c               *Conn
	serverHello     *serverHelloMsg
	hello           *clientHelloMsg
	suite           *cipherSuite
	finishedHash    finishedHash
	masterSecret    []byte
	preMasterSecret []byte
	session         *ClientSessionState
}

type CacheKeyGenerator interface {
	Key(net.Addr) string
}

type ClientFingerprintConfiguration struct {
	// Version in the handshake header
	HandshakeVersion uint16

	// if len == 32, it will specify the client random.
	// Otherwise, the field will be random
	// except the top 4 bytes if InsertTimestamp is true
	ClientRandom    []byte
	InsertTimestamp bool

	// if RandomSessionID > 0, will overwrite SessionID w/ that many
	// random bytes when a session resumption occurs
	RandomSessionID int
	SessionID       []byte

	// These fields will appear exactly in order in the ClientHello
	CipherSuites       []uint16
	CompressionMethods []uint8
	Extensions         []ClientExtension

	// Optional, both must be non-nil, or neither.
	// Custom Session cache implementations allowed
	SessionCache ClientSessionCache
	CacheKey     CacheKeyGenerator
}

type ClientExtension interface {
	// Produce the bytes on the wire for this extension, type and length included
	Marshal() []byte

	// Function will return an error if zTLS does not implement the necessary features for this extension
	CheckImplemented() error

	// Modifies the config to reflect the state of the extension
	WriteToConfig(*Config) error
}

func (c *ClientFingerprintConfiguration) CheckImplementedExtensions() error {
	for _, ext := range c.Extensions {
		if err := ext.CheckImplemented(); err != nil {
			return err
		}
	}
	return nil
}

func (c *clientHelloMsg) WriteToConfig(config *Config) error {
	config.NextProtos = c.alpnProtocols
	config.CipherSuites = c.cipherSuites
	config.MaxVersion = c.vers
	config.ClientRandom = c.random
	config.CurvePreferences = c.supportedCurves
	config.ExtendedRandom = c.extendedRandomEnabled
	config.ForceSessionTicketExt = c.ticketSupported
	config.ExtendedMasterSecret = c.extendedMasterSecret
	config.SignedCertificateTimestampExt = c.sctEnabled
	return nil
}

func (c *ClientFingerprintConfiguration) WriteToConfig(config *Config) error {
	config.NextProtos = []string{}
	config.CipherSuites = c.CipherSuites
	config.MaxVersion = c.HandshakeVersion
	config.ClientRandom = c.ClientRandom
	config.CurvePreferences = []CurveID{}
	config.HeartbeatEnabled = false
	config.ExtendedRandom = false
	config.ForceSessionTicketExt = false
	config.ExtendedMasterSecret = false
	config.SignedCertificateTimestampExt = false
	for _, ext := range c.Extensions {
		if err := ext.WriteToConfig(config); err != nil {
			return err
		}
	}
	return nil
}

func currentTimestamp() ([]byte, error) {
	t := time.Now().Unix()
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, t)
	return buf.Bytes(), err
}

func (c *ClientFingerprintConfiguration) marshal(config *Config) ([]byte, error) {
	if err := c.CheckImplementedExtensions(); err != nil {
		return nil, err
	}
	head := make([]byte, 38)
	head[0] = 1
	head[4] = uint8(c.HandshakeVersion >> 8)
	head[5] = uint8(c.HandshakeVersion)
	if len(c.ClientRandom) == 32 {
		copy(head[6:38], c.ClientRandom[0:32])
	} else {
		start := 6
		if c.InsertTimestamp {
			t, err := currentTimestamp()
			if err != nil {
				return nil, err
			}
			copy(head[start:start+4], t)
			start = start + 4
		}
		_, err := io.ReadFull(config.rand(), head[start:38])
		if err != nil {
			return nil, errors.New("tls: short read from Rand: " + err.Error())
		}
	}

	if len(c.SessionID) >= 256 {
		return nil, errors.New("tls: SessionID too long")
	}
	sessionID := make([]byte, len(c.SessionID)+1)
	sessionID[0] = uint8(len(c.SessionID))
	if len(c.SessionID) > 0 {
		copy(sessionID[1:], c.SessionID)
	}

	ciphers := make([]byte, 2+2*len(c.CipherSuites))
	ciphers[0] = uint8(len(c.CipherSuites) >> 7)
	ciphers[1] = uint8(len(c.CipherSuites) << 1)
	for i, suite := range c.CipherSuites {
		if !config.ForceSuites {
			found := false
			for _, impl := range implementedCipherSuites {
				if impl.id == suite {
					found = true
				}
			}
			if !found {
				return nil, errors.New(fmt.Sprintf("tls: unimplemented cipher suite %d", suite))
			}
		}

		ciphers[2+i*2] = uint8(suite >> 8)
		ciphers[3+i*2] = uint8(suite)
	}

	if len(c.CompressionMethods) >= 256 {
		return nil, errors.New("tls: Too many compression methods")
	}
	compressions := make([]byte, len(c.CompressionMethods)+1)
	compressions[0] = uint8(len(c.CompressionMethods))
	if len(c.CompressionMethods) > 0 {
		copy(compressions[1:], c.CompressionMethods)
		if c.CompressionMethods[0] != 0 {
			return nil, errors.New(fmt.Sprintf("tls: unimplemented compression method %d", c.CompressionMethods[0]))
		}
		if len(c.CompressionMethods) > 1 {
			return nil, errors.New(fmt.Sprintf("tls: unimplemented compression method %d", c.CompressionMethods[1]))
		}
	} else {
		return nil, errors.New("tls: no compression method")
	}

	var extensions []byte
	for _, ext := range c.Extensions {
		extensions = append(extensions, ext.Marshal()...)
	}
	if len(extensions) > 0 {
		length := make([]byte, 2)
		length[0] = uint8(len(extensions) >> 8)
		length[1] = uint8(len(extensions))
		extensions = append(length, extensions...)
	}
	helloArray := [][]byte{head, sessionID, ciphers, compressions, extensions}
	hello := []byte{}
	for _, b := range helloArray {
		hello = append(hello, b...)
	}
	lengthOnTheWire := len(hello) - 4
	if lengthOnTheWire >= 1<<24 {
		return nil, errors.New("ClientHello message too long")
	}
	hello[1] = uint8(lengthOnTheWire >> 16)
	hello[2] = uint8(lengthOnTheWire >> 8)
	hello[3] = uint8(lengthOnTheWire)

	return hello, nil
}

func (c *Conn) makeClientHello() (*clientHelloMsg, map[CurveID]tls13KeyShare, error) {
	config := c.config
	if len(config.ServerName) == 0 && !config.InsecureSkipVerify {
		return nil, nil, errors.New("tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config")
	}

	nextProtosLength := 0
	for _, proto := range config.NextProtos {
		if l := len(proto); l == 0 || l > 255 {
			return nil, nil, errors.New("tls: invalid NextProtos value")
		} else {
			nextProtosLength += 1 + l
		}
	}
	if nextProtosLength > 0xffff {
		return nil, nil, errors.New("tls: NextProtos values too large")
	}

	supportedVersions := config.supportedVersions()
	if len(supportedVersions) == 0 {
		return nil, nil, errors.New("tls: no supported versions satisfy MinVersion and MaxVersion")
	}

	clientHelloVersion := config.maxSupportedVersion()
	// The version at the beginning of the ClientHello was capped at TLS 1.2
	// for compatibility reasons. The supported_versions extension is used
	// to negotiate versions now. See RFC 8446, Section 4.2.1.
	if clientHelloVersion > VersionTLS12 {
		clientHelloVersion = VersionTLS12
	}

	hello := &clientHelloMsg{
		vers:                         clientHelloVersion,
		compressionMethods:           []uint8{compressionNone},
		random:                       make([]byte, 32),
		sessionId:                    make([]byte, 32),
		ocspStapling:                 true,
		scts:                         true,
		serverName:                   hostnameInSNI(config.ServerName),
		supportedCurves:              config.curvePreferences(),
		supportedPoints:              []uint8{pointFormatUncompressed},
		secureRenegotiationSupported: true,
		alpnProtocols:                config.NextProtos,
		supportedVersions:            supportedVersions,
	}

	if c.handshakes > 0 {
		hello.secureRenegotiation = c.clientFinished[:]
	}

	possibleCipherSuites := config.cipherSuites()
	hello.cipherSuites = make([]uint16, 0, len(possibleCipherSuites))

	if !config.ForceSuites {
		for _, suiteId := range possibleCipherSuites {
			for _, suite := range cipherSuites {
				if suite.id != suiteId {
					continue
				}
				// Don't advertise TLS 1.2-only cipher suites unless
				// we're attempting TLS 1.2.
				if hello.vers < VersionTLS12 && suite.flags&suiteTLS12 != 0 {
					break
				}
				hello.cipherSuites = append(hello.cipherSuites, suiteId)
				break
			}
		}
	} else {
		hello.cipherSuites = append(hello.cipherSuites, possibleCipherSuites...)
	}

	_, err := io.ReadFull(config.rand(), hello.random)
	if err != nil {
		return nil, nil, errors.New("tls: short read from Rand: " + err.Error())
	}

	// A random session ID is used to detect when the server accepted a ticket
	// and is resuming a session (see RFC 5077). In TLS 1.3, it's always set as
	// a compatibility measure (see RFC 8446, Section 4.1.2).
	if _, err := io.ReadFull(config.rand(), hello.sessionId); err != nil {
		return nil, nil, errors.New("tls: short read from Rand: " + err.Error())
	}

	if hello.vers >= VersionTLS12 {
		hello.supportedSignatureAlgorithms = supportedSignatureAlgorithms
	}

	var keySharesByGroup map[CurveID]tls13KeyShare
	if hello.supportedVersions[0] == VersionTLS13 {
		if !config.ForceSuites {
			// If ForceSuites == true, we've already appended the user's ciphers above
			hello.cipherSuites = append(hello.cipherSuites, config.cipherSuitesTLS13()...)
		}

		prefs := config.curvePreferences()
		if len(prefs) == 0 {
			return nil, nil, errors.New("tls: no supported key exchange mechanisms (no curve preferences)")
		}

		// By default, send a single key_share. If one of the hybrid PQ
		// algorithms is explicitly enabled as the top preference, also
		// send a fallback.
		shareGroups := []CurveID{prefs[0]}
		switch prefs[0] {
		case X25519MLKEM768:
			if slices.Contains(prefs, X25519) {
				shareGroups = append(shareGroups, X25519)
			}
		case SecP256r1MLKEM768:
			if slices.Contains(prefs, CurveP256) {
				shareGroups = append(shareGroups, CurveP256)
			}
		case SecP384r1MLKEM1024:
			if slices.Contains(prefs, CurveP384) {
				shareGroups = append(shareGroups, CurveP384)
			}
		}

		hello.keyShares = make([]keyShare, 0, len(shareGroups))
		keySharesByGroup = make(map[CurveID]tls13KeyShare, len(shareGroups))

		seen := make(map[CurveID]struct{}, len(shareGroups))
		for _, group := range shareGroups {
			if _, ok := seen[group]; ok {
				continue
			}
			seen[group] = struct{}{}

			ks, genErr := generateTLS13KeyShare(config.rand(), group)
			if genErr != nil {
				// If a group is not supported/implemented, skip it.
				continue
			}

			hello.keyShares = append(hello.keyShares, keyShare{
				group: group,
				data:  ks.PublicKey(),
			})
			keySharesByGroup[group] = ks
		}

		if len(hello.keyShares) == 0 {
			return nil, nil, errors.New("tls: no supported key exchange mechanisms (no key shares)")
		}
	}

	return hello, keySharesByGroup, nil
}

func (c *Conn) clientHandshake() (err error) {
	if c.config == nil {
		c.config = defaultConfig()
	}
	var hello *clientHelloMsg
	var helloBytes []byte
	var session *ClientSessionState
	var sessionCache ClientSessionCache
	var cacheKey string
	var keySharesByGroup map[CurveID]tls13KeyShare

	// This may be a renegotiation handshake, in which case some fields
	// need to be reset.
	c.didResume = false

	// first, let's check if a ClientFingerprintConfiguration template was provided by the config
	if c.config.ClientFingerprintConfiguration != nil {
		if err := c.config.ClientFingerprintConfiguration.WriteToConfig(c.config); err != nil {
			return err
		}
		session = nil
		sessionCache = c.config.ClientFingerprintConfiguration.SessionCache
		if sessionCache != nil {
			if c.config.ClientFingerprintConfiguration.CacheKey == nil {
				return errors.New("tls: must specify CacheKey if SessionCache is defined in Config.ClientFingerprintConfiguration")
			}
			cacheKey = c.config.ClientFingerprintConfiguration.CacheKey.Key(c.conn.RemoteAddr())
			candidateSession, ok := sessionCache.Get(cacheKey)
			if ok {
				cipherSuiteOk := false
				for _, id := range c.config.ClientFingerprintConfiguration.CipherSuites {
					if id == candidateSession.cipherSuite {
						cipherSuiteOk = true
						break
					}
				}
				versOk := candidateSession.vers >= c.config.minSupportedVersion() &&
					candidateSession.vers <= c.config.ClientFingerprintConfiguration.HandshakeVersion
				if versOk && cipherSuiteOk {
					session = candidateSession
				}
			}
		}
		for i, ext := range c.config.ClientFingerprintConfiguration.Extensions {
			switch casted := ext.(type) {
			case *SessionTicketExtension:
				if casted.Autopopulate {
					if session == nil {
						if !c.config.ForceSessionTicketExt {
							c.config.ClientFingerprintConfiguration.Extensions[i] = &NullExtension{}
						}
					} else {
						c.config.ClientFingerprintConfiguration.Extensions[i] = &SessionTicketExtension{session.sessionTicket, true}
						if c.config.ClientFingerprintConfiguration.RandomSessionID > 0 {
							c.config.ClientFingerprintConfiguration.SessionID = make([]byte, c.config.ClientFingerprintConfiguration.RandomSessionID)
							if _, err := io.ReadFull(c.config.rand(), c.config.ClientFingerprintConfiguration.SessionID); err != nil {
								c.sendAlert(AlertInternalError)
								return errors.New("tls: short read from Rand: " + err.Error())
							}

						}
					}
				}
			}
		}
		var err error
		helloBytes, err = c.config.ClientFingerprintConfiguration.marshal(c.config)
		if err != nil {
			return err
		}
		hello = &clientHelloMsg{}
		if ok := hello.unmarshal(helloBytes); !ok {
			return errors.New("tls: incompatible ClientFingerprintConfiguration")
		}

		// next, let's check if a ClientHello template was provided by the user
	} else if c.config.ExternalClientHello != nil {

		hello = new(clientHelloMsg)

		if !hello.unmarshal(c.config.ExternalClientHello) {
			return errors.New("could not read the ClientHello provided")
		}
		if err := hello.WriteToConfig(c.config); err != nil {
			return err
		}

		// update the SNI with one name, whether or not the extension was already there
		hello.serverName = c.config.ServerName

		// then we update the 'raw' value of the message
		hello.raw = nil
		helloBytes = hello.marshal()

		session = nil
		sessionCache = nil
	} else {

		hello, keySharesByGroup, err = c.makeClientHello()
		if err != nil {
			return err
		}
	}
	c.serverName = hello.serverName

	cacheKey, session, earlySecret, binderKey := c.loadSession(hello)
	if cacheKey != "" && session != nil {
		defer func() {
			// If we got a handshake failure when resuming a session, throw away
			// the session ticket. See RFC 5077, Section 3.2.
			//
			// RFC 8446 makes no mention of dropping tickets on failure, but it
			// does require servers to abort on invalid binders, so we need to
			// delete tickets to recover from a corrupted PSK.
			if err != nil {
				c.config.ClientSessionCache.Put(cacheKey, nil)
			}
		}()
	}

	c.handshakeLog = new(ServerHandshake)

	if c.config.ForceSessionTicketExt {
		hello.ticketSupported = true
	}

	if c.config.SignedCertificateTimestampExt {
		hello.sctEnabled = true
	}

	if _, err := c.WriteRecord(recordTypeHandshake, hello.marshal()); err != nil {
		return err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	c.handshakeLog.ClientHello = hello.MakeLog()

	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		c.sendAlert(AlertUnexpectedMessage)
		return unexpectedMessageError(serverHello, msg)
	}
	c.handshakeLog.ServerHello = serverHello.MakeLog()

	if err := c.pickTLSVersion(serverHello); err != nil {
		return err
	}

	// If we are negotiating a protocol version that's lower than what we
	// support, check for the server downgrade canaries.
	// See RFC 8446, Section 4.1.3.
	maxVers := c.config.maxSupportedVersion()
	tls12Downgrade := string(serverHello.random[24:]) == downgradeCanaryTLS12
	tls11Downgrade := string(serverHello.random[24:]) == downgradeCanaryTLS11
	if maxVers == VersionTLS13 && c.vers <= VersionTLS12 && (tls12Downgrade || tls11Downgrade) ||
		maxVers == VersionTLS12 && c.vers <= VersionTLS11 && tls11Downgrade {
		c.sendAlert(AlertIllegalParameter)
		return errors.New("tls: downgrade attempt detected, possibly due to a MitM attack or a broken middlebox")
	}

	if c.vers == VersionTLS13 {
		hs := &clientHandshakeStateTLS13{
			c:                c,
			serverHello:      serverHello,
			hello:            hello,
			keySharesByGroup: keySharesByGroup,
			session:          session,
			earlySecret:      earlySecret,
			binderKey:        binderKey,
		}

		// In TLS 1.3, session tickets are delivered after the handshake.
		return hs.handshake()
	}

	hs := &clientHandshakeState{
		c:           c,
		serverHello: serverHello,
		hello:       hello,
		session:     session,
	}

	if err := hs.handshake(); err != nil {
		return err
	}

	if hs.session == nil {
		c.handshakeLog.SessionTicket = nil
	} else {
		c.handshakeLog.SessionTicket = hs.session.MakeLog()
	}

	c.handshakeLog.KeyMaterial = hs.MakeLog()

	// If we had a successful handshake and hs.session is different from
	// the one already cached - cache a new one.
	if cacheKey != "" && hs.session != nil && session != hs.session {
		c.config.ClientSessionCache.Put(cacheKey, hs.session)
	}

	return nil
}

func (c *Conn) loadSession(hello *clientHelloMsg) (cacheKey string,
	session *ClientSessionState, earlySecret, binderKey []byte) {
	if c.config.SessionTicketsDisabled || c.config.ClientSessionCache == nil {
		return "", nil, nil, nil
	}

	hello.ticketSupported = true

	if hello.supportedVersions[0] == VersionTLS13 {
		// Require DHE on resumption as it guarantees forward secrecy against
		// compromise of the session ticket key. See RFC 8446, Section 4.2.9.
		hello.pskModes = []uint8{pskModeDHE}
	}

	// Session resumption is not allowed if renegotiating because
	// renegotiation is primarily used to allow a client to send a client
	// certificate, which would be skipped if session resumption occurred.
	if c.handshakes != 0 {
		return "", nil, nil, nil
	}

	// Try to resume a previously negotiated TLS session, if available.
	cacheKey = clientSessionCacheKey(c.conn.RemoteAddr(), c.config)
	session, ok := c.config.ClientSessionCache.Get(cacheKey)
	if !ok || session == nil {
		return cacheKey, nil, nil, nil
	}

	// Check that version used for the previous session is still valid.
	versOk := false
	for _, v := range hello.supportedVersions {
		if v == session.vers {
			versOk = true
			break
		}
	}
	if !versOk {
		return cacheKey, nil, nil, nil
	}

	// Check that the cached server certificate is not expired, and that it's
	// valid for the ServerName. This should be ensured by the cache key, but
	// protect the application from a faulty ClientSessionCache implementation.
	if !c.config.InsecureSkipVerify {
		if len(session.verifiedChains) == 0 {
			// The original connection had InsecureSkipVerify, while this doesn't.
			return cacheKey, nil, nil, nil
		}
		serverCert := session.serverCertificates[0]
		if c.config.time().After(serverCert.NotAfter) {
			// Expired certificate, delete the entry.
			c.config.ClientSessionCache.Put(cacheKey, nil)
			return cacheKey, nil, nil, nil
		}
		if err := serverCert.VerifyHostname(c.config.ServerName); err != nil {
			return cacheKey, nil, nil, nil
		}
	}

	if session.vers != VersionTLS13 {
		// In TLS 1.2 the cipher suite must match the resumed session. Ensure we
		// are still offering it.
		if mutualCipherSuite(hello.cipherSuites, session.cipherSuite) == nil {
			return cacheKey, nil, nil, nil
		}

		hello.sessionTicket = session.sessionTicket
		return
	}

	// Check that the session ticket is not expired.
	if c.config.time().After(session.useBy) {
		c.config.ClientSessionCache.Put(cacheKey, nil)
		return cacheKey, nil, nil, nil
	}

	// In TLS 1.3 the KDF hash must match the resumed session. Ensure we
	// offer at least one cipher suite with that hash.
	cipherSuite := cipherSuiteTLS13ByID(session.cipherSuite)
	if cipherSuite == nil {
		return cacheKey, nil, nil, nil
	}
	cipherSuiteOk := false
	for _, offeredID := range hello.cipherSuites {
		offeredSuite := cipherSuiteTLS13ByID(offeredID)
		if offeredSuite != nil && offeredSuite.hash == cipherSuite.hash {
			cipherSuiteOk = true
			break
		}
	}
	if !cipherSuiteOk {
		return cacheKey, nil, nil, nil
	}

	// Set the pre_shared_key extension. See RFC 8446, Section 4.2.11.1.
	ticketAge := uint32(c.config.time().Sub(session.receivedAt) / time.Millisecond)
	identity := pskIdentity{
		label:               session.sessionTicket,
		obfuscatedTicketAge: ticketAge + session.ageAdd,
	}
	hello.pskIdentities = []pskIdentity{identity}
	hello.pskBinders = [][]byte{make([]byte, cipherSuite.hash.Size())}

	// Compute the PSK binders. See RFC 8446, Section 4.2.11.2.
	psk := cipherSuite.expandLabel(session.masterSecret, "resumption",
		session.nonce, cipherSuite.hash.Size())
	earlySecret = cipherSuite.extract(psk, nil)
	binderKey = cipherSuite.deriveSecret(earlySecret, resumptionBinderLabel, nil)
	transcript := cipherSuite.hash.New()
	transcript.Write(hello.marshalWithoutBinders())
	pskBinders := [][]byte{cipherSuite.finishedHash(binderKey, transcript)}
	hello.updateBinders(pskBinders)

	return
}

func (c *Conn) pickTLSVersion(serverHello *serverHelloMsg) error {
	peerVersion := serverHello.vers
	if serverHello.supportedVersion != 0 {
		peerVersion = serverHello.supportedVersion
	}

	vers, ok := c.config.mutualVersion([]uint16{peerVersion})
	if !ok {
		c.sendAlert(AlertProtocolVersion)
		return fmt.Errorf("tls: server selected unsupported protocol version %x", peerVersion)
	}

	c.vers = vers
	c.haveVers = true
	c.in.version = vers
	c.out.version = vers

	return nil
}

// Does the handshake, either a full one or resumes old session. Requires hs.c,
// hs.hello, hs.serverHello, and, optionally, hs.session to be set.
func (hs *clientHandshakeState) handshake() error {
	c := hs.c

	isResume, err := hs.processServerHello()
	if err != nil {
		return err
	}

	hs.finishedHash = newFinishedHash(c.vers, hs.suite)

	// No signatures of the handshake are needed in a resumption.
	// Otherwise, in a full handshake, if we don't have any certificates
	// configured then we will never send a CertificateVerify message and
	// thus no signatures are needed in that case either.
	if isResume || (len(c.config.Certificates) == 0 && c.config.GetClientCertificate == nil) {
		hs.finishedHash.discardHandshakeBuffer()
	}

	hs.finishedHash.Write(hs.hello.marshal())
	hs.finishedHash.Write(hs.serverHello.marshal())

	c.buffering = true
	c.didResume = isResume
	if isResume {
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
		c.clientFinishedIsFirst = false
		// Make sure the connection is still being verified whether or not this
		// is a resumption. Resumptions currently don't reverify certificates so
		// they don't call verifyServerCertificate. See Issue 31641.
		if c.config.VerifyConnection != nil {
			if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
				c.sendAlert(AlertBadCertificate)
				return err
			}
		}
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
	} else {
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
		c.clientFinishedIsFirst = true
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
	}

	c.ekm = ekmFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random)
	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

func (hs *clientHandshakeState) pickCipherSuite() error {
	if hs.suite = mutualCipherSuite(hs.hello.cipherSuites, hs.serverHello.cipherSuite); hs.suite == nil {
		hs.c.sendAlert(AlertHandshakeFailure)
		return errors.New("tls: server chose an unconfigured cipher suite")
	}

	hs.c.cipherSuite = hs.suite.id
	return nil
}

func (hs *clientHandshakeState) doFullHandshake() error {
	c := hs.c

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	certMsg, ok := msg.(*certificateMsg)
	if !ok || len(certMsg.certificates) == 0 {
		c.sendAlert(AlertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}
	hs.finishedHash.Write(certMsg.marshal())

	msg, err = c.readHandshake()
	if err != nil {
		return err
	}

	cs, ok := msg.(*certificateStatusMsg)
	if ok {
		// RFC4366 on Certificate Status Request:
		// The server MAY return a "certificate_status" message.

		if !hs.serverHello.ocspStapling {
			// If a server returns a "CertificateStatus" message, then the
			// server MUST have included an extension of type "status_request"
			// with empty "extension_data" in the extended server hello.

			c.sendAlert(AlertUnexpectedMessage)
			return errors.New("tls: received unexpected CertificateStatus message")
		}
		hs.finishedHash.Write(cs.marshal())

		c.ocspResponse = cs.response

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	c.handshakeLog.ServerCertificates = certMsg.MakeLog()

	if c.handshakes == 0 {
		// If this is the first handshake on a connection, process and
		// (optionally) verify the server's certificates.
		if err := c.verifyServerCertificate(certMsg.certificates); err != nil {
			return err
		}
	} else {
		// This is a renegotiation handshake. We require that the
		// server's identity (i.e. leaf certificate) is unchanged and
		// thus any previous trust decision is still valid.
		//
		// See https://mitls.org/pages/attacks/3SHAKE for the
		// motivation behind this requirement.
		if !bytes.Equal(c.peerCertificates[0].Raw, certMsg.certificates[0]) {
			c.sendAlert(AlertBadCertificate)
			return errors.New("tls: server's identity changed during renegotiation")
		}
	}

	keyAgreement := hs.suite.ka(c.vers)

	skx, ok := msg.(*serverKeyExchangeMsg)
	if ok {
		hs.finishedHash.Write(skx.marshal())
		err = keyAgreement.processServerKeyExchange(c.config, hs.hello, hs.serverHello, c.peerCertificates[0], skx)
		if err != nil {
			c.sendAlert(AlertUnexpectedMessage)
			return err
		}
		c.handshakeLog.ServerKeyExchange = skx.MakeLog(keyAgreement)

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	var chainToSend *Certificate
	var certRequested bool
	certReq, ok := msg.(*certificateRequestMsg)
	if ok {
		certRequested = true
		hs.finishedHash.Write(certReq.marshal())

		cri := certificateRequestInfoFromMsg(c.vers, certReq)
		if chainToSend, err = c.getClientCertificate(cri); err != nil {
			c.sendAlert(AlertInternalError)
			return err
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	shd, ok := msg.(*serverHelloDoneMsg)
	if !ok {
		c.sendAlert(AlertUnexpectedMessage)
		return unexpectedMessageError(shd, msg)
	}
	hs.finishedHash.Write(shd.marshal())

	// If the server requested a certificate then we have to send a
	// Certificate message, even if it's empty because we don't have a
	// certificate to send.
	if certRequested {
		certMsg = new(certificateMsg)
		certMsg.certificates = chainToSend.Certificate
		hs.finishedHash.Write(certMsg.marshal())
		if _, err := c.WriteRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
			return err
		}
	}

	var ckx *clientKeyExchangeMsg
	hs.preMasterSecret, ckx, err = keyAgreement.generateClientKeyExchange(c.config, hs.hello, c.peerCertificates[0])
	if err != nil {
		c.sendAlert(AlertInternalError)
		return err
	}

	c.handshakeLog.ClientKeyExchange = ckx.MakeLog(keyAgreement)

	if ckx != nil {
		hs.finishedHash.Write(ckx.marshal())
		if _, err := c.WriteRecord(recordTypeHandshake, ckx.marshal()); err != nil {
			return err
		}
	}

	if chainToSend != nil && len(chainToSend.Certificate) > 0 {
		certVerify := &certificateVerifyMsg{}

		key, ok := chainToSend.PrivateKey.(crypto.Signer)
		if !ok {
			c.sendAlert(AlertInternalError)
			return fmt.Errorf("tls: client certificate private key of type %T does not implement crypto.Signer", chainToSend.PrivateKey)
		}

		var sigType uint8
		var sigHash crypto.Hash
		if c.vers >= VersionTLS12 {
			signatureAlgorithm, err := selectSignatureScheme(c.vers, chainToSend, certReq.supportedSignatureAlgorithms)
			if err != nil {
				c.sendAlert(AlertIllegalParameter)
				return err
			}
			sigType, sigHash, err = typeAndHashFromSignatureScheme(signatureAlgorithm)
			if err != nil {
				return c.sendAlert(AlertInternalError)
			}
			certVerify.hasSignatureAlgorithm = true
			certVerify.signatureAlgorithm = signatureAlgorithm
		} else {
			sigType, sigHash, err = legacyTypeAndHashFromPublicKey(key.Public())
			if err != nil {
				c.sendAlert(AlertIllegalParameter)
				return err
			}
		}

		signed := hs.finishedHash.hashForClientCertificate(sigType, sigHash, hs.masterSecret)
		signOpts := crypto.SignerOpts(sigHash)
		if sigType == signatureRSAPSS {
			signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
		}
		certVerify.signature, err = key.Sign(c.config.rand(), signed, signOpts)
		if err != nil {
			c.sendAlert(AlertInternalError)
			return err
		}

		hs.finishedHash.Write(certVerify.marshal())
		if _, err := c.WriteRecord(recordTypeHandshake, certVerify.marshal()); err != nil {
			return err
		}
	}

	hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, hs.preMasterSecret, hs.hello.random, hs.serverHello.random)
	if err := c.config.writeKeyLog(keyLogLabelTLS12, hs.hello.random, hs.masterSecret); err != nil {
		c.sendAlert(AlertInternalError)
		return errors.New("tls: failed to write to key log: " + err.Error())
	}

	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

func (hs *clientHandshakeState) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
	var clientCipher, serverCipher interface{}
	var clientHash, serverHash hash.Hash
	if hs.suite.cipher != nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, false /* not for reading */)
		clientHash = hs.suite.mac(clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, true /* for reading */)
		serverHash = hs.suite.mac(serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	c.in.prepareCipherSpec(c.vers, serverCipher, serverHash)
	c.out.prepareCipherSpec(c.vers, clientCipher, clientHash)
	return nil
}

func (hs *clientHandshakeState) serverResumedSession() bool {
	// If the server responded with the same sessionId then it means the
	// sessionTicket is being used to resume a TLS session.
	return hs.session != nil && hs.hello.sessionId != nil &&
		bytes.Equal(hs.serverHello.sessionId, hs.hello.sessionId)
}

func (hs *clientHandshakeState) processServerHello() (bool, error) {
	c := hs.c

	if err := hs.pickCipherSuite(); err != nil {
		return false, err
	}

	if hs.serverHello.compressionMethod != compressionNone {
		c.sendAlert(AlertUnexpectedMessage)
		return false, errors.New("tls: server selected unsupported compression format")
	}

	if c.handshakes == 0 && hs.serverHello.secureRenegotiationSupported {
		c.secureRenegotiation = true
		if len(hs.serverHello.secureRenegotiation) != 0 {
			c.sendAlert(AlertHandshakeFailure)
			return false, errors.New("tls: initial handshake had non-empty renegotiation extension")
		}
	}

	if c.handshakes > 0 && c.secureRenegotiation {
		var expectedSecureRenegotiation [24]byte
		copy(expectedSecureRenegotiation[:], c.clientFinished[:])
		copy(expectedSecureRenegotiation[12:], c.serverFinished[:])
		if !bytes.Equal(hs.serverHello.secureRenegotiation, expectedSecureRenegotiation[:]) {
			c.sendAlert(AlertHandshakeFailure)
			return false, errors.New("tls: incorrect renegotiation extension contents")
		}
	}

	if hs.serverHello.alpnProtocol != "" {
		if len(hs.hello.alpnProtocols) == 0 {
			c.sendAlert(AlertUnsupportedExtension)
			return false, errors.New("tls: server advertised unrequested ALPN extension")
		}
		if mutualProtocol([]string{hs.serverHello.alpnProtocol}, hs.hello.alpnProtocols) == "" {
			c.sendAlert(AlertUnsupportedExtension)
			return false, errors.New("tls: server selected unadvertised ALPN protocol")
		}
		c.clientProtocol = hs.serverHello.alpnProtocol
	}

	c.scts = hs.serverHello.scts

	if !hs.serverResumedSession() {
		return false, nil
	}

	if hs.session.vers != c.vers {
		c.sendAlert(AlertHandshakeFailure)
		return false, errors.New("tls: server resumed a session with a different version")
	}

	if hs.session.cipherSuite != hs.suite.id {
		c.sendAlert(AlertHandshakeFailure)
		return false, errors.New("tls: server resumed a session with a different cipher suite")
	}

	// Restore masterSecret, peerCerts, and ocspResponse from previous state
	hs.masterSecret = hs.session.masterSecret
	c.peerCertificates = hs.session.serverCertificates
	c.verifiedChains = hs.session.verifiedChains
	c.ocspResponse = hs.session.ocspResponse
	// Let the ServerHello SCTs override the session SCTs from the original
	// connection, if any are provided
	if len(c.scts) == 0 && len(hs.session.scts) != 0 {
		c.scts = hs.session.scts
	}

	return true, nil
}

func (hs *clientHandshakeState) readFinished(out []byte) error {
	c := hs.c

	if err := c.readChangeCipherSpec(); err != nil {
		return err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	serverFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(AlertUnexpectedMessage)
		return unexpectedMessageError(serverFinished, msg)
	}
	c.handshakeLog.ServerFinished = serverFinished.MakeLog()

	verify := hs.finishedHash.serverSum(hs.masterSecret)
	if len(verify) != len(serverFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, serverFinished.verifyData) != 1 {
		c.sendAlert(AlertHandshakeFailure)
		return errors.New("tls: server's Finished message was incorrect")
	}
	hs.finishedHash.Write(serverFinished.marshal())
	copy(out, verify)
	return nil
}

func (hs *clientHandshakeState) readSessionTicket() error {
	if !hs.serverHello.ticketSupported {
		return nil
	}

	c := hs.c
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	sessionTicketMsg, ok := msg.(*newSessionTicketMsg)
	if !ok {
		c.sendAlert(AlertUnexpectedMessage)
		return unexpectedMessageError(sessionTicketMsg, msg)
	}
	hs.finishedHash.Write(sessionTicketMsg.marshal())

	hs.session = &ClientSessionState{
		sessionTicket:      sessionTicketMsg.ticket,
		vers:               c.vers,
		cipherSuite:        hs.suite.id,
		masterSecret:       hs.masterSecret,
		serverCertificates: c.peerCertificates,
		lifetimeHint:       sessionTicketMsg.lifetimeHint,
		verifiedChains:     c.verifiedChains,
		receivedAt:         c.config.time(),
		ocspResponse:       c.ocspResponse,
		scts:               c.scts,
	}

	return nil
}

func (hs *clientHandshakeState) sendFinished(out []byte) error {
	c := hs.c

	if _, err := c.WriteRecord(recordTypeChangeCipherSpec, []byte{1}); err != nil {
		return err
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.clientSum(hs.masterSecret)
	hs.finishedHash.Write(finished.marshal())
	c.handshakeLog.ClientFinished = finished.MakeLog()

	if _, err := c.WriteRecord(recordTypeHandshake, finished.marshal()); err != nil {
		return err
	}
	copy(out, finished.verifyData)
	return nil
}

// verifyServerCertificate parses and verifies the provided chain, setting
// c.verifiedChains and c.peerCertificates or sending the appropriate alert.
func (c *Conn) verifyServerCertificate(certificates [][]byte) error {
	certs := make([]*x509.Certificate, len(certificates))
	for i, asn1Data := range certificates {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			c.sendAlert(AlertBadCertificate)
			return errors.New("tls: failed to parse certificate from server: " + err.Error())
		}
		certs[i] = cert
	}

	opts := x509.VerifyOptions{
		Roots:         c.config.RootCAs,
		CurrentTime:   c.config.time(),
		DNSName:       c.config.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	var err error
	var validation *x509.Validation
	c.verifiedChains, validation, err = certs[0].ValidateWithStupidDetail(opts)
	c.handshakeLog.ServerCertificates.addParsed(certs, validation)
	if !c.config.InsecureSkipVerify {
		if err != nil {
			c.sendAlert(AlertBadCertificate)
			return err
		}
	}

	switch certs[0].PublicKey.(type) {
	case *rsa.PublicKey, *x509.AugmentedECDSA, *ecdsa.PublicKey, ed25519.PublicKey:
		break
	default:
		c.sendAlert(AlertUnsupportedCertificate)
		return fmt.Errorf("tls: server's certificate contains an unsupported type of public key: %T", certs[0].PublicKey)
	}

	c.peerCertificates = certs

	if c.config.VerifyPeerCertificate != nil {
		if err := c.config.VerifyPeerCertificate(certificates, c.verifiedChains); err != nil {
			c.sendAlert(AlertBadCertificate)
			return err
		}
	}

	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			c.sendAlert(AlertBadCertificate)
			return err
		}
	}

	return nil
}

// certificateRequestInfoFromMsg generates a CertificateRequestInfo from a TLS
// <= 1.2 CertificateRequest, making an effort to fill in missing information.
func certificateRequestInfoFromMsg(vers uint16, certReq *certificateRequestMsg) *CertificateRequestInfo {
	cri := &CertificateRequestInfo{
		AcceptableCAs: certReq.certificateAuthorities,
		Version:       vers,
	}

	var rsaAvail, ecAvail bool
	for _, certType := range certReq.certificateTypes {
		switch certType {
		case certTypeRSASign:
			rsaAvail = true
		case certTypeECDSASign:
			ecAvail = true
		}
	}

	if !certReq.hasSignatureAlgorithm {
		// Prior to TLS 1.2, signature schemes did not exist. In this case we
		// make up a list based on the acceptable certificate types, to help
		// GetClientCertificate and SupportsCertificate select the right certificate.
		// The hash part of the SignatureScheme is a lie here, because
		// TLS 1.0 and 1.1 always use MD5+SHA1 for RSA and SHA1 for ECDSA.
		switch {
		case rsaAvail && ecAvail:
			cri.SignatureSchemes = []SignatureScheme{
				ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512,
				PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512, PKCS1WithSHA1,
			}
		case rsaAvail:
			cri.SignatureSchemes = []SignatureScheme{
				PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512, PKCS1WithSHA1,
			}
		case ecAvail:
			cri.SignatureSchemes = []SignatureScheme{
				ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512,
			}
		}
		return cri
	}

	// Filter the signature schemes based on the certificate types.
	// See RFC 5246, Section 7.4.4 (where it calls this "somewhat complicated").
	cri.SignatureSchemes = make([]SignatureScheme, 0, len(certReq.supportedSignatureAlgorithms))
	for _, sigScheme := range certReq.supportedSignatureAlgorithms {
		sigType, _, err := typeAndHashFromSignatureScheme(sigScheme)
		if err != nil {
			continue
		}
		switch sigType {
		case signatureECDSA, signatureEd25519:
			if ecAvail {
				cri.SignatureSchemes = append(cri.SignatureSchemes, sigScheme)
			}
		case signatureRSAPSS, signaturePKCS1v15:
			if rsaAvail {
				cri.SignatureSchemes = append(cri.SignatureSchemes, sigScheme)
			}
		}
	}

	return cri
}

func (c *Conn) getClientCertificate(cri *CertificateRequestInfo) (*Certificate, error) {
	if c.config.GetClientCertificate != nil {
		return c.config.GetClientCertificate(cri)
	}

	for _, chain := range c.config.Certificates {
		if err := cri.SupportsCertificate(&chain); err != nil {
			continue
		}
		return &chain, nil
	}

	// No acceptable certificate found. Don't send a certificate.
	return new(Certificate), nil
}

// clientSessionCacheKey returns a key used to cache sessionTickets that could
// be used to resume previously negotiated TLS sessions with a server.
func clientSessionCacheKey(serverAddr net.Addr, config *Config) string {
	if len(config.ServerName) > 0 {
		return config.ServerName
	}
	return serverAddr.String()
}

// mutualProtocol finds the mutual ALPN protocol given list of possible
// protocols and a list of the preference order.
func mutualProtocol(protos, preferenceProtos []string) string {
	for _, s := range preferenceProtos {
		for _, c := range protos {
			if s == c {
				return s
			}
		}
	}
	return ""
}

// hostnameInSNI converts name into an appropriate hostname for SNI.
// Literal IP addresses and absolute FQDNs are not permitted as SNI values.
// See RFC 6066, Section 3.
func hostnameInSNI(name string) string {
	host := name
	if len(host) > 0 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if i := strings.LastIndex(host, "%"); i > 0 {
		host = host[:i]
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}
