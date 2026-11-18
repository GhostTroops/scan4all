// Copyright 2022 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/refraction-networking/utls/internal/fips140tls"
	"github.com/refraction-networking/utls/internal/hpke"
	"github.com/refraction-networking/utls/internal/tls13"
)

// This function is called by (*clientHandshakeStateTLS13).readServerCertificate()
// to retrieve the certificate out of a message read by (*Conn).readHandshake()
func (hs *clientHandshakeStateTLS13) utlsReadServerCertificate(msg any) (processedMsg any, err error) {
	for _, ext := range hs.uconn.Extensions {
		switch ext.(type) {
		case *UtlsCompressCertExtension:
			// Included Compressed Certificate extension
			if len(hs.uconn.certCompressionAlgs) > 0 {
				compressedCertMsg, ok := msg.(*utlsCompressedCertificateMsg)
				if ok {
					if err = transcriptMsg(compressedCertMsg, hs.transcript); err != nil {
						return nil, err
					}
					msg, err = hs.decompressCert(*compressedCertMsg)
					if err != nil {
						return nil, fmt.Errorf("tls: failed to decompress certificate message: %w", err)
					} else {
						return msg, nil
					}
				}
			}
		default:
			continue
		}
	}
	return nil, nil
}

// called by (*clientHandshakeStateTLS13).utlsReadServerCertificate() when UtlsCompressCertExtension is used
func (hs *clientHandshakeStateTLS13) decompressCert(m utlsCompressedCertificateMsg) (*certificateMsgTLS13, error) {
	var (
		decompressed io.Reader
		compressed   = bytes.NewReader(m.compressedCertificateMessage)
		c            = hs.c
	)

	// Check to see if the peer responded with an algorithm we advertised.
	supportedAlg := false
	for _, alg := range hs.uconn.certCompressionAlgs {
		if m.algorithm == uint16(alg) {
			supportedAlg = true
		}
	}
	if !supportedAlg {
		c.sendAlert(alertBadCertificate)
		return nil, fmt.Errorf("unadvertised algorithm (%d)", m.algorithm)
	}

	switch CertCompressionAlgo(m.algorithm) {
	case CertCompressionBrotli:
		decompressed = brotli.NewReader(compressed)

	case CertCompressionZlib:
		rc, err := zlib.NewReader(compressed)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return nil, fmt.Errorf("failed to open zlib reader: %w", err)
		}
		defer rc.Close()
		decompressed = rc

	case CertCompressionZstd:
		rc, err := zstd.NewReader(compressed)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return nil, fmt.Errorf("failed to open zstd reader: %w", err)
		}
		defer rc.Close()
		decompressed = rc

	default:
		c.sendAlert(alertBadCertificate)
		return nil, fmt.Errorf("unsupported algorithm (%d)", m.algorithm)
	}

	rawMsg := make([]byte, m.uncompressedLength+4) // +4 for message type and uint24 length field
	rawMsg[0] = typeCertificate
	rawMsg[1] = uint8(m.uncompressedLength >> 16)
	rawMsg[2] = uint8(m.uncompressedLength >> 8)
	rawMsg[3] = uint8(m.uncompressedLength)

	n, err := decompressed.Read(rawMsg[4:])
	if err != nil && !errors.Is(err, io.EOF) {
		c.sendAlert(alertBadCertificate)
		return nil, err
	}
	if n < len(rawMsg)-4 {
		// If, after decompression, the specified length does not match the actual length, the party
		// receiving the invalid message MUST abort the connection with the "bad_certificate" alert.
		// https://datatracker.ietf.org/doc/html/rfc8879#section-4
		c.sendAlert(alertBadCertificate)
		return nil, fmt.Errorf("decompressed len (%d) does not match specified len (%d)", n, m.uncompressedLength)
	}
	certMsg := new(certificateMsgTLS13)
	if !certMsg.unmarshal(rawMsg) {
		return nil, c.sendAlert(alertUnexpectedMessage)
	}
	return certMsg, nil
}

// to be called in (*clientHandshakeStateTLS13).handshake(),
// after hs.readServerFinished() and before hs.sendClientCertificate()
func (hs *clientHandshakeStateTLS13) serverFinishedReceived() error {
	if err := hs.sendClientEncryptedExtensions(); err != nil {
		return err
	}
	return nil
}

func (hs *clientHandshakeStateTLS13) sendClientEncryptedExtensions() error {
	c := hs.c
	clientEncryptedExtensions := new(utlsClientEncryptedExtensionsMsg)
	if c.utls.applicationSettingsCodepoint != 0 {
		clientEncryptedExtensions.applicationSettingsCodepoint = c.utls.applicationSettingsCodepoint
		clientEncryptedExtensions.applicationSettings = c.utls.localApplicationSettings
		if _, err := c.writeHandshakeRecord(clientEncryptedExtensions, hs.transcript); err != nil {
			return err
		}
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) utlsReadServerParameters(encryptedExtensions *encryptedExtensionsMsg) error {
	hs.c.utls.peerApplicationSettings = encryptedExtensions.utls.applicationSettings
	hs.c.utls.applicationSettingsCodepoint = encryptedExtensions.utls.applicationSettingsCodepoint

	if hs.c.utls.applicationSettingsCodepoint != 0 {
		if hs.uconn.vers < VersionTLS13 {
			return errors.New("tls: server sent application settings at invalid version")
		}
		if len(hs.uconn.clientProtocol) == 0 {
			return errors.New("tls: server sent application settings without ALPN")
		}

		// Check if the ALPN selected by the server exists in the client's list.
		if alps, ok := hs.uconn.config.ApplicationSettings[hs.serverHello.alpnProtocol]; ok {
			hs.c.utls.localApplicationSettings = alps
		} else {
			// return errors.New("tls: server selected ALPN doesn't match a client ALPS")
			return nil // ignore if client doesn't have ALPS in use.
			// TODO: is this a issue or not?
		}
	}

	return nil
}

func (c *Conn) makeClientHelloForApplyPreset() (*clientHelloMsg, *keySharePrivateKeys, *echClientContext, error) {
	config := c.config

	// [UTLS SECTION START]
	if len(config.ServerName) == 0 && !config.InsecureSkipVerify && len(config.InsecureServerNameToVerify) == 0 {
		return nil, nil, nil, errors.New("tls: at least one of ServerName, InsecureSkipVerify or InsecureServerNameToVerify must be specified in the tls.Config")
	}
	// [UTLS SECTION END]

	nextProtosLength := 0
	for _, proto := range config.NextProtos {
		if l := len(proto); l == 0 || l > 255 {
			return nil, nil, nil, errors.New("tls: invalid NextProtos value")
		} else {
			nextProtosLength += 1 + l
		}
	}
	if nextProtosLength > 0xffff {
		return nil, nil, nil, errors.New("tls: NextProtos values too large")
	}

	supportedVersions := config.supportedVersions(roleClient)
	if len(supportedVersions) == 0 {
		return nil, nil, nil, errors.New("tls: no supported versions satisfy MinVersion and MaxVersion")
	}
	maxVersion := config.maxSupportedVersion(roleClient)

	hello := &clientHelloMsg{
		vers:                         maxVersion,
		compressionMethods:           []uint8{compressionNone},
		random:                       make([]byte, 32),
		extendedMasterSecret:         true,
		ocspStapling:                 true,
		scts:                         true,
		serverName:                   hostnameInSNI(config.ServerName),
		supportedCurves:              config.curvePreferences(maxVersion),
		supportedPoints:              []uint8{pointFormatUncompressed},
		secureRenegotiationSupported: true,
		alpnProtocols:                config.NextProtos,
		supportedVersions:            supportedVersions,
	}

	// The version at the beginning of the ClientHello was capped at TLS 1.2
	// for compatibility reasons. The supported_versions extension is used
	// to negotiate versions now. See RFC 8446, Section 4.2.1.
	if hello.vers > VersionTLS12 {
		hello.vers = VersionTLS12
	}

	if c.handshakes > 0 {
		hello.secureRenegotiation = c.clientFinished[:]
	}

	preferenceOrder := cipherSuitesPreferenceOrder
	if !hasAESGCMHardwareSupport {
		preferenceOrder = cipherSuitesPreferenceOrderNoAES
	}
	configCipherSuites := config.cipherSuites()
	hello.cipherSuites = make([]uint16, 0, len(configCipherSuites))

	for _, suiteId := range preferenceOrder {
		suite := mutualCipherSuite(configCipherSuites, suiteId)
		if suite == nil {
			continue
		}
		// Don't advertise TLS 1.2-only cipher suites unless
		// we're attempting TLS 1.2.
		if maxVersion < VersionTLS12 && suite.flags&suiteTLS12 != 0 {
			continue
		}
		hello.cipherSuites = append(hello.cipherSuites, suiteId)
	}

	_, err := io.ReadFull(config.rand(), hello.random)
	if err != nil {
		return nil, nil, nil, errors.New("tls: short read from Rand: " + err.Error())
	}

	// A random session ID is used to detect when the server accepted a ticket
	// and is resuming a session (see RFC 5077). In TLS 1.3, it's always set as
	// a compatibility measure (see RFC 8446, Section 4.1.2).
	//
	// The session ID is not set for QUIC connections (see RFC 9001, Section 8.4).
	if c.quic == nil {
		hello.sessionId = make([]byte, 32)
		if _, err := io.ReadFull(config.rand(), hello.sessionId); err != nil {
			return nil, nil, nil, errors.New("tls: short read from Rand: " + err.Error())
		}
	}

	if maxVersion >= VersionTLS12 {
		hello.supportedSignatureAlgorithms = supportedSignatureAlgorithms()
	}
	if testingOnlyForceClientHelloSignatureAlgorithms != nil {
		hello.supportedSignatureAlgorithms = testingOnlyForceClientHelloSignatureAlgorithms
	}

	var keyShareKeys *keySharePrivateKeys
	if hello.supportedVersions[0] == VersionTLS13 {
		// Reset the list of ciphers when the client only supports TLS 1.3.
		if len(hello.supportedVersions) == 1 {
			hello.cipherSuites = nil
		}
		if fips140tls.Required() {
			hello.cipherSuites = append(hello.cipherSuites, defaultCipherSuitesTLS13FIPS...)
		} else if hasAESGCMHardwareSupport {
			hello.cipherSuites = append(hello.cipherSuites, defaultCipherSuitesTLS13...)
		} else {
			hello.cipherSuites = append(hello.cipherSuites, defaultCipherSuitesTLS13NoAES...)
		}

		if len(hello.supportedCurves) == 0 {
			return nil, nil, nil, errors.New("tls: no supported elliptic curves for ECDHE")
		}
		// curveID := hello.supportedCurves[0]
		// keyShareKeys = &keySharePrivateKeys{curveID: curveID}
		// // Note that if X25519MLKEM768 is supported, it will be first because
		// // the preference order is fixed.
		// if curveID == X25519MLKEM768 {
		// 	keyShareKeys.ecdhe, err = generateECDHEKey(config.rand(), X25519)
		// 	if err != nil {
		// 		return nil, nil, nil, err
		// 	}
		// 	seed := make([]byte, mlkem.SeedSize)
		// 	if _, err := io.ReadFull(config.rand(), seed); err != nil {
		// 		return nil, nil, nil, err
		// 	}
		// 	keyShareKeys.mlkem, err = mlkem.NewDecapsulationKey768(seed)
		// 	if err != nil {
		// 		return nil, nil, nil, err
		// 	}
		// 	mlkemEncapsulationKey := keyShareKeys.mlkem.EncapsulationKey().Bytes()
		// 	x25519EphemeralKey := keyShareKeys.ecdhe.PublicKey().Bytes()
		// 	hello.keyShares = []keyShare{
		// 		{group: X25519MLKEM768, data: append(mlkemEncapsulationKey, x25519EphemeralKey...)},
		// 	}
		// 	// If both X25519MLKEM768 and X25519 are supported, we send both key
		// 	// shares (as a fallback) and we reuse the same X25519 ephemeral
		// 	// key, as allowed by draft-ietf-tls-hybrid-design-09, Section 3.2.
		// 	if slices.Contains(hello.supportedCurves, X25519) {
		// 		hello.keyShares = append(hello.keyShares, keyShare{group: X25519, data: x25519EphemeralKey})
		// 	}
		// } else {
		// 	if _, ok := curveForCurveID(curveID); !ok {
		// 		return nil, nil, nil, errors.New("tls: CurvePreferences includes unsupported curve")
		// 	}
		// 	keyShareKeys.ecdhe, err = generateECDHEKey(config.rand(), curveID)
		// 	if err != nil {
		// 		return nil, nil, nil, err
		// 	}
		// 	hello.keyShares = []keyShare{{group: curveID, data: keyShareKeys.ecdhe.PublicKey().Bytes()}}
		// }
	}

	// [UTLS] We don't need this, since it is not ready yet
	// if c.quic != nil {
	// 	p, err := c.quicGetTransportParameters()
	// 	if err != nil {
	// 		return nil, nil, nil, err
	// 	}
	// 	if p == nil {
	// 		p = []byte{}
	// 	}
	// 	hello.quicTransportParameters = p
	// }

	var ech *echClientContext
	if c.config.EncryptedClientHelloConfigList != nil {
		if c.config.MinVersion != 0 && c.config.MinVersion < VersionTLS13 {
			return nil, nil, nil, errors.New("tls: MinVersion must be >= VersionTLS13 if EncryptedClientHelloConfigList is populated")
		}
		if c.config.MaxVersion != 0 && c.config.MaxVersion <= VersionTLS12 {
			return nil, nil, nil, errors.New("tls: MaxVersion must be >= VersionTLS13 if EncryptedClientHelloConfigList is populated")
		}
		echConfigs, err := parseECHConfigList(c.config.EncryptedClientHelloConfigList)
		if err != nil {
			return nil, nil, nil, err
		}
		echConfig := pickECHConfig(echConfigs)
		if echConfig == nil {
			return nil, nil, nil, errors.New("tls: EncryptedClientHelloConfigList contains no valid configs")
		}
		ech = &echClientContext{config: echConfig}
		hello.encryptedClientHello = []byte{1} // indicate inner hello
		// We need to explicitly set these 1.2 fields to nil, as we do not
		// marshal them when encoding the inner hello, otherwise transcripts
		// will later mismatch.
		hello.supportedPoints = nil
		hello.ticketSupported = false
		hello.secureRenegotiationSupported = false
		hello.extendedMasterSecret = false

		echPK, err := hpke.ParseHPKEPublicKey(ech.config.KemID, ech.config.PublicKey)
		if err != nil {
			return nil, nil, nil, err
		}
		suite, err := pickECHCipherSuite(ech.config.SymmetricCipherSuite)
		if err != nil {
			return nil, nil, nil, err
		}
		ech.kdfID, ech.aeadID = suite.KDFID, suite.AEADID
		info := append([]byte("tls ech\x00"), ech.config.raw...)
		ech.encapsulatedKey, ech.hpkeContext, err = hpke.SetupSender(ech.config.KemID, suite.KDFID, suite.AEADID, echPK, info)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	return hello, keyShareKeys, ech, nil
}

// clientHandshakeWithOneState checks that exactly one expected state is set (1.2 or 1.3)
// and performs client TLS handshake with that state
func (c *UConn) clientHandshake(ctx context.Context) (err error) {
	// [uTLS section begins]
	hello := c.HandshakeState.Hello.getPrivatePtr()
	ech := c.echCtx
	defer func() { c.HandshakeState.Hello = hello.getPublicPtr() }()

	sessionIsLocked := c.utls.sessionController.isSessionLocked()

	// after this point exactly 1 out of 2 HandshakeState pointers is non-nil,
	// useTLS13 variable tells which pointer
	// [uTLS section ends]

	if c.config == nil {
		c.config = defaultConfig()
	}

	// This may be a renegotiation handshake, in which case some fields
	// need to be reset.
	c.didResume = false

	// [uTLS section begins]
	// don't make new ClientHello, use hs.hello
	// preserve the checks from beginning and end of makeClientHello()
	if len(c.config.ServerName) == 0 && !c.config.InsecureSkipVerify && len(c.config.InsecureServerNameToVerify) == 0 {
		return errors.New("tls: at least one of ServerName, InsecureSkipVerify or InsecureServerNameToVerify must be specified in the tls.Config")
	}

	nextProtosLength := 0
	for _, proto := range c.config.NextProtos {
		if l := len(proto); l == 0 || l > 255 {
			return errors.New("tls: invalid NextProtos value")
		} else {
			nextProtosLength += 1 + l
		}
	}

	if nextProtosLength > 0xffff {
		return errors.New("tls: NextProtos values too large")
	}

	if c.handshakes > 0 {
		hello.secureRenegotiation = c.clientFinished[:]
	}

	var (
		session     *SessionState
		earlySecret *tls13.EarlySecret
		binderKey   []byte
	)
	if !sessionIsLocked {
		// [uTLS section ends]

		session, earlySecret, binderKey, err = c.loadSession(hello)

		// [uTLS section start]
	} else {
		session = c.HandshakeState.Session

		if c.HandshakeState.State13.EarlySecret != nil && session != nil {
			cipherSuite := cipherSuiteTLS13ByID(session.cipherSuite)
			earlySecret = tls13.NewEarlySecretFromSecret(cipherSuite.hash.New, c.HandshakeState.State13.EarlySecret)
		}

		binderKey = c.HandshakeState.State13.BinderKey
	}
	// [uTLS section ends]
	if err != nil {
		return err
	}
	if session != nil {
		defer func() {
			// If we got a handshake failure when resuming a session, throw away
			// the session ticket. See RFC 5077, Section 3.2.
			//
			// RFC 8446 makes no mention of dropping tickets on failure, but it
			// does require servers to abort on invalid binders, so we need to
			// delete tickets to recover from a corrupted PSK.
			if err != nil {
				if cacheKey := c.clientSessionCacheKey(); cacheKey != "" {
					c.config.ClientSessionCache.Put(cacheKey, nil)
				}
			}
		}()
	}

	if ech != nil && c.clientHelloBuildStatus != BuildByUtls {
		// Split hello into inner and outer
		ech.innerHello = hello.clone()

		// Overwrite the server name in the outer hello with the public facing
		// name.
		hello.serverName = string(ech.config.PublicName)
		// Generate a new random for the outer hello.
		hello.random = make([]byte, 32)
		_, err = io.ReadFull(c.config.rand(), hello.random)
		if err != nil {
			return errors.New("tls: short read from Rand: " + err.Error())
		}

		// NOTE: we don't do PSK GREASE, in line with boringssl, it's meant to
		// work around _possibly_ broken middleboxes, but there is little-to-no
		// evidence that this is actually a problem.

		if err := computeAndUpdateOuterECHExtension(hello, ech.innerHello, ech, true); err != nil {
			return err
		}
	}

	c.serverName = hello.serverName

	if _, err := c.writeHandshakeRecord(hello, nil); err != nil {
		return err
	}

	if hello.earlyData {
		suite := cipherSuiteTLS13ByID(session.cipherSuite)
		transcript := suite.hash.New()
		if err := transcriptMsg(hello, transcript); err != nil {
			return err
		}
		earlyTrafficSecret := earlySecret.ClientEarlyTrafficSecret(transcript)
		c.quicSetWriteSecret(QUICEncryptionLevelEarly, suite.id, earlyTrafficSecret)
	}

	// serverHelloMsg is not included in the transcript
	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}

	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverHello, msg)
	}

	if err := c.pickTLSVersion(serverHello); err != nil {
		return err
	}

	// If we are negotiating a protocol version that's lower than what we
	// support, check for the server downgrade canaries.
	// See RFC 8446, Section 4.1.3.
	maxVers := c.config.maxSupportedVersion(roleClient)
	tls12Downgrade := string(serverHello.random[24:]) == downgradeCanaryTLS12
	tls11Downgrade := string(serverHello.random[24:]) == downgradeCanaryTLS11
	if maxVers == VersionTLS13 && c.vers <= VersionTLS12 && (tls12Downgrade || tls11Downgrade) ||
		maxVers == VersionTLS12 && c.vers <= VersionTLS11 && tls11Downgrade {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: downgrade attempt detected, possibly due to a MitM attack or a broken middlebox")
	}

	// uTLS: do not create new handshakeState, use existing one
	c.HandshakeState.ServerHello = serverHello.getPublicPtr()
	if c.vers == VersionTLS13 {
		hs13 := c.HandshakeState.toPrivate13()
		hs13.serverHello = serverHello
		hs13.hello = hello
		hs13.echContext = ech
		if c.HandshakeState.State13.EarlySecret != nil && session.cipherSuite != 0 {
			hs13.earlySecret = tls13.NewEarlySecretFromSecret(cipherSuiteTLS13ByID(session.cipherSuite).hash.New, c.HandshakeState.State13.EarlySecret)
		}
		if c.HandshakeState.MasterSecret != nil && session.cipherSuite != 0 {
			hs13.masterSecret = tls13.NewMasterSecretFromSecret(cipherSuiteTLS13ByID(session.cipherSuite).hash.New, c.HandshakeState.MasterSecret)
		}
		if !sessionIsLocked {
			hs13.earlySecret = earlySecret
			hs13.binderKey = binderKey
			hs13.session = session
		}
		hs13.ctx = ctx
		// In TLS 1.3, session tickets are delivered after the handshake.
		err = hs13.handshake()
		if handshakeState := hs13.toPublic13(); handshakeState != nil {
			c.HandshakeState = *handshakeState
		}
		return err
	}

	hs12 := c.HandshakeState.toPrivate12()
	hs12.serverHello = serverHello
	hs12.hello = hello
	hs12.ctx = ctx
	hs12.session = session
	err = hs12.handshake()
	if handshakeState := hs12.toPublic12(); handshakeState != nil {
		c.HandshakeState = *handshakeState
	}
	if err != nil {
		return err
	}
	return nil
}

func (c *UConn) echTranscriptMsg(outer *clientHelloMsg, echCtx *echClientContext) (err error) {
	// Recreate the inner ClientHello from its compressed form using server's decodeInnerClientHello function.
	// See https://github.com/refraction-networking/utls/blob/e430876b1d82fdf582efc57f3992d448e7ab3d8a/ech.go#L276-L283
	encodedInner, err := encodeInnerClientHelloReorderOuterExts(echCtx.innerHello, int(echCtx.config.MaxNameLength), c.extensionsList())
	if err != nil {
		return err
	}

	decodedInner, err := decodeInnerClientHello(outer, encodedInner)
	if err != nil {
		return err
	}

	if err := transcriptMsg(decodedInner, echCtx.innerTranscript); err != nil {
		return err
	}

	return nil
}
