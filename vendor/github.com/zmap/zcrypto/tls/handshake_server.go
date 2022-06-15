// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"

	"github.com/zmap/zcrypto/x509"
)

// serverHandshakeState contains details of a server handshake in progress.
// It's discarded once the handshake has completed.
type serverHandshakeState struct {
	c                     *Conn
	clientHello           *clientHelloMsg
	hello                 *serverHelloMsg
	suite                 *cipherSuite
	ellipticOk            bool
	ecdsaOk               bool
	sessionState          *sessionState
	finishedHash          finishedHash
	masterSecret          []byte
	certsFromClient       [][]byte
	cert                  *Certificate
	preMasterSecret       []byte
	cachedClientHelloInfo *ClientHelloInfo
}

// serverHandshake performs a TLS handshake as a server.
func (c *Conn) serverHandshake() error {
	// If this is the first server handshake, we generate a random key to
	// encrypt the tickets with.
	c.config.serverInitOnce.Do(c.config.serverInit)

	hs := serverHandshakeState{
		c: c,
	}
	isResume, err := hs.readClientHello()
	if err != nil {
		return err
	}

	// For an overview of TLS handshaking, see https://tools.ietf.org/html/rfc5246#section-7.3
	if !c.config.DontBufferHandshakes {
		c.buffering = true
		defer c.flush()
	}
	if isResume {
		// The client has included a session ticket and so we do an abbreviated handshake.
		if err := hs.doResumeHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.sendFinished(); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
		if err := hs.readFinished(); err != nil {
			return err
		}
		c.didResume = true
	} else {
		// The client didn't include a session ticket, or it wasn't
		// valid so we do a full handshake.
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.readFinished(); err != nil {
			return err
		}
		if !c.config.DontBufferHandshakes {
			c.buffering = true
			defer c.flush()
		}
		if err := hs.sendSessionTicket(); err != nil {
			return err
		}
		if err := hs.sendFinished(); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
	}

	c.handshakeLog.KeyMaterial = hs.MakeLog()

	c.handshakeComplete = true

	return nil
}

// readClientHello reads a ClientHello message from the client and decides
// whether we will perform session resumption.
func (hs *serverHandshakeState) readClientHello() (isResume bool, err error) {
	c := hs.c
	c.handshakeLog = new(ServerHandshake)

	msg, err := c.readHandshake()
	if err != nil {
		return false, err
	}
	var ok bool
	hs.clientHello, ok = msg.(*clientHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return false, unexpectedMessageError(hs.clientHello, msg)
	}
	c.clientHelloRaw = hs.clientHello.raw
	c.clientCiphers = hs.clientHello.cipherSuites
	c.handshakeLog.ClientHello = hs.clientHello.MakeLog()

	if c.config.GetConfigForClient != nil {
		if newConfig, err := c.config.GetConfigForClient(hs.clientHelloInfo()); err != nil {
			c.sendAlert(alertInternalError)
			return false, err
		} else if newConfig != nil {
			newConfig.mutex.Lock()
			newConfig.originalConfig = c.config
			newConfig.mutex.Unlock()

			newConfig.serverInitOnce.Do(newConfig.serverInit)
			c.config = newConfig
		}
	}

	c.vers, ok = c.config.mutualVersion(hs.clientHello.vers)
	if !ok {
		c.sendAlert(alertProtocolVersion)
		return false, fmt.Errorf("tls: client offered an unsupported, maximum protocol version of %x", hs.clientHello.vers)
	}
	c.haveVers = true

	hs.finishedHash = newFinishedHash(c.vers, hs.suite)
	hs.finishedHash.Write(hs.clientHello.marshal())

	hs.hello = new(serverHelloMsg)

	supportedCurve := false
	preferredCurves := c.config.curvePreferences()
Curves:
	for _, curve := range hs.clientHello.supportedCurves {
		for _, supported := range preferredCurves {
			if supported == curve {
				supportedCurve = true
				break Curves
			}
		}
	}

	supportedPointFormat := false
	for _, pointFormat := range hs.clientHello.supportedPoints {
		if pointFormat == pointFormatUncompressed {
			supportedPointFormat = true
			break
		}
	}
	hs.ellipticOk = supportedCurve && supportedPointFormat

	foundCompression := false
	// We only support null compression, so check that the client offered it.
	for _, compression := range hs.clientHello.compressionMethods {
		if compression == compressionNone {
			foundCompression = true
			break
		}
	}

	if !foundCompression {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: client does not support uncompressed connections")
	}

	hs.hello.vers = c.vers
	hs.hello.random = make([]byte, 32)
	_, err = io.ReadFull(c.config.rand(), hs.hello.random)
	if err != nil {
		c.sendAlert(alertInternalError)
		return false, err
	}
	hs.hello.secureRenegotiation = hs.clientHello.secureRenegotiation
	hs.hello.compressionMethod = compressionNone
	hs.hello.extendedMasterSecret = c.vers >= VersionTLS10 && hs.clientHello.extendedMasterSecret && c.config.ExtendedMasterSecret
	if len(hs.clientHello.serverName) > 0 {
		c.serverName = hs.clientHello.serverName
	}
	if len(hs.clientHello.alpnProtocols) > 0 {
		if selectedProto, fallback := mutualProtocol(hs.clientHello.alpnProtocols, c.config.NextProtos); !fallback {
			hs.hello.alpnProtocol = selectedProto
			c.clientProtocol = selectedProto
		}
	} else {
		// Although sending an empty NPN extension is reasonable, Firefox has
		// had a bug around this. Best to send nothing at all if
		// c.config.NextProtos is empty. See
		// https://code.google.com/p/go/issues/detail?id=5445.
		if hs.clientHello.nextProtoNeg && len(c.config.NextProtos) > 0 {
			hs.hello.nextProtoNeg = true
			hs.hello.nextProtos = c.config.NextProtos
		}
	}

	if len(c.config.Certificates) == 0 {
		c.sendAlert(alertInternalError)
		return false, errors.New("tls: no certificates configured")
	}
	hs.cert = &c.config.Certificates[0]
	if len(hs.clientHello.serverName) > 0 {
		hs.cert = c.config.getCertificateForName(hs.clientHello.serverName)
	}

	_, hs.ecdsaOk = hs.cert.PrivateKey.(*ecdsa.PrivateKey)

	if hs.checkForResumption() {
		return true, nil
	}

	var preferenceList, supportedList []uint16
	if c.config.PreferServerCipherSuites {
		preferenceList = c.config.cipherSuites()
		supportedList = hs.clientHello.cipherSuites
	} else {
		preferenceList = hs.clientHello.cipherSuites
		supportedList = c.config.cipherSuites()
	}

	for _, id := range preferenceList {
		if hs.suite = c.tryCipherSuite(id, supportedList, c.vers, hs.ellipticOk, hs.ecdsaOk); hs.suite != nil {
			break
		}
	}

	if hs.suite == nil {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: no cipher suite supported by both client and server")
	}

	return false, nil
}

// checkForResumption returns true if we should perform resumption on this connection.
func (hs *serverHandshakeState) checkForResumption() bool {
	c := hs.c

	if c.config.SessionTicketsDisabled {
		return false
	}

	var ok bool
	if hs.sessionState, ok = c.decryptTicket(hs.clientHello.sessionTicket); !ok {
		return false
	}

	if hs.sessionState.vers > hs.clientHello.vers {
		return false
	}
	if vers, ok := c.config.mutualVersion(hs.sessionState.vers); !ok || vers != hs.sessionState.vers {
		return false
	}

	cipherSuiteOk := false
	// Check that the client is still offering the ciphersuite in the session.
	for _, id := range hs.clientHello.cipherSuites {
		if id == hs.sessionState.cipherSuite {
			cipherSuiteOk = true
			break
		}
	}
	if !cipherSuiteOk {
		return false
	}

	// Check that we also support the ciphersuite from the session.
	hs.suite = c.tryCipherSuite(hs.sessionState.cipherSuite, c.config.cipherSuites(), hs.sessionState.vers, hs.ellipticOk, hs.ecdsaOk)
	if hs.suite == nil {
		return false
	}

	sessionHasClientCerts := len(hs.sessionState.certificates) != 0
	needClientCerts := c.config.ClientAuth == RequireAnyClientCert || c.config.ClientAuth == RequireAndVerifyClientCert
	if needClientCerts && !sessionHasClientCerts {
		return false
	}
	if sessionHasClientCerts && c.config.ClientAuth == NoClientCert {
		return false
	}

	return true
}

func (hs *serverHandshakeState) doResumeHandshake() error {
	c := hs.c

	hs.hello.cipherSuite = hs.suite.id
	// We echo the client's session ID in the ServerHello to let it know
	// that we're doing a resumption.
	hs.hello.sessionId = hs.clientHello.sessionId
	hs.finishedHash.Write(hs.hello.marshal())
	c.writeRecord(recordTypeHandshake, hs.hello.marshal())
	c.handshakeLog.ServerHello = hs.hello.MakeLog()

	if len(hs.sessionState.certificates) > 0 {
		if _, err := hs.processCertsFromClient(hs.sessionState.certificates); err != nil {
			return err
		}
	}

	hs.masterSecret = hs.sessionState.masterSecret
	c.extendedMasterSecret = hs.sessionState.extendedMasterSecret

	return nil
}

func (hs *serverHandshakeState) doFullHandshake() error {
	c := hs.c

	if hs.clientHello.ocspStapling && len(hs.cert.OCSPStaple) > 0 {
		hs.hello.ocspStapling = true
	}

	hs.hello.ticketSupported = hs.clientHello.ticketSupported && !c.config.SessionTicketsDisabled
	hs.hello.cipherSuite = hs.suite.id
	c.extendedMasterSecret = hs.hello.extendedMasterSecret
	hs.finishedHash.Write(hs.hello.marshal())
	c.writeRecord(recordTypeHandshake, hs.hello.marshal())
	c.handshakeLog.ServerHello = hs.hello.MakeLog()

	certMsg := new(certificateMsg)
	certMsg.certificates = hs.cert.Certificate
	hs.finishedHash.Write(certMsg.marshal())
	c.writeRecord(recordTypeHandshake, certMsg.marshal())
	c.handshakeLog.ServerCertificates = certMsg.MakeLog()

	if hs.hello.ocspStapling {
		certStatus := new(certificateStatusMsg)
		certStatus.statusType = statusTypeOCSP
		certStatus.response = hs.cert.OCSPStaple
		hs.finishedHash.Write(certStatus.marshal())
		c.writeRecord(recordTypeHandshake, certStatus.marshal())
	}

	keyAgreement := hs.suite.ka(c.vers)
	skx, err := keyAgreement.generateServerKeyExchange(c.config, hs.cert, hs.clientHello, hs.hello)
	if err != nil {
		c.sendAlert(alertHandshakeFailure)
		return err
	}
	if skx != nil {
		hs.finishedHash.Write(skx.marshal())
		c.writeRecord(recordTypeHandshake, skx.marshal())
		c.handshakeLog.ServerKeyExchange = skx.MakeLog(keyAgreement)
	}

	if c.config.ClientAuth >= RequestClientCert {
		// Request a client certificate
		certReq := new(certificateRequestMsg)
		certReq.certificateTypes = []byte{
			byte(certTypeRSASign),
			byte(certTypeECDSASign),
		}
		if c.vers >= VersionTLS12 {
			certReq.hasSignatureAndHash = true
			certReq.signatureAndHashes = c.config.signatureAndHashesForServer()
		}

		// An empty list of certificateAuthorities signals to
		// the client that it may send any certificate in response
		// to our request. When we know the CAs we trust, then
		// we can send them down, so that the client can choose
		// an appropriate certificate to give to us.
		if c.config.ClientCAs != nil {
			certReq.certificateAuthorities = c.config.ClientCAs.Subjects()
		}
		hs.finishedHash.Write(certReq.marshal())
		c.writeRecord(recordTypeHandshake, certReq.marshal())
	}

	helloDone := new(serverHelloDoneMsg)
	hs.finishedHash.Write(helloDone.marshal())
	c.writeRecord(recordTypeHandshake, helloDone.marshal())

	if _, err := c.flush(); err != nil {
		return err
	}

	var pub crypto.PublicKey // public key for client auth, if any

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	var ok bool
	// If we requested a client certificate, then the client must send a
	// certificate message, even if it's empty.
	if c.config.ClientAuth >= RequestClientCert {
		if certMsg, ok = msg.(*certificateMsg); !ok {
			c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(certMsg, msg)
		}
		hs.finishedHash.Write(certMsg.marshal())

		if len(certMsg.certificates) == 0 {
			// The client didn't actually send a certificate
			switch c.config.ClientAuth {
			case RequireAnyClientCert, RequireAndVerifyClientCert:
				c.sendAlert(alertBadCertificate)
				return errors.New("tls: client didn't provide a certificate")
			}
		}

		pub, err = hs.processCertsFromClient(certMsg.certificates)
		if err != nil {
			return err
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	// Get client key exchange
	ckx, ok := msg.(*clientKeyExchangeMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(ckx, msg)
	}
	hs.finishedHash.Write(ckx.marshal())

	preMasterSecret, err := keyAgreement.processClientKeyExchange(c.config, hs.cert, ckx)
	if err != nil {
		c.sendAlert(alertHandshakeFailure)
		return err
	}
	c.handshakeLog.ClientKeyExchange = ckx.MakeLog(keyAgreement)

	hs.preMasterSecret = make([]byte, len(preMasterSecret))
	copy(hs.preMasterSecret, preMasterSecret)

	if c.extendedMasterSecret {
		hs.masterSecret = extendedMasterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.finishedHash)
	} else {
		hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.clientHello.random, hs.hello.random)
	}

	// If we received a client cert in response to our certificate request message,
	// the client will send us a certificateVerifyMsg immediately after the
	// clientKeyExchangeMsg.  This message is a digest of all preceding
	// handshake-layer messages that is signed using the private key corresponding
	// to the client's certificate. This allows us to verify that the client is in
	// possession of the private key of the certificate.
	if len(c.peerCertificates) > 0 {
		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
		certVerify, ok := msg.(*certificateVerifyMsg)
		if !ok {
			c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(certVerify, msg)
		}

		// Determine the signature type.
		var signatureAndHash SigAndHash
		if certVerify.hasSignatureAndHash {
			signatureAndHash = certVerify.signatureAndHash
			if !isSupportedSignatureAndHash(signatureAndHash, c.config.signatureAndHashesForServer()) {
				return errors.New("tls: unsupported hash function for client certificate")
			}
		} else {
			// Before TLS 1.2 the signature algorithm was implicit
			// from the key type, and only one hash per signature
			// algorithm was possible. Leave the hash as zero.
			switch pub.(type) {
			case *ecdsa.PublicKey:
				signatureAndHash.Signature = signatureECDSA
			case *rsa.PublicKey:
				signatureAndHash.Signature = signatureRSA
			}
		}

		switch key := pub.(type) {
		case *x509.AugmentedECDSA:
			if signatureAndHash.Signature != signatureECDSA {
				err = errors.New("tls: bad signature type for client's ECDSA certificate")
				break
			}
			ecdsaSig := new(ecdsaSignature)
			if _, err = asn1.Unmarshal(certVerify.signature, ecdsaSig); err != nil {
				break
			}
			if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
				err = errors.New("ECDSA signature contained zero or negative values")
				break
			}
			var digest []byte
			digest, _, err = hs.finishedHash.hashForClientCertificate(signatureAndHash, hs.masterSecret)
			if err != nil {
				break
			}
			if !ecdsa.Verify(key.Pub, digest, ecdsaSig.R, ecdsaSig.S) {
				err = errors.New("ECDSA verification failure")
				break
			}
		case *ecdsa.PublicKey:
			if signatureAndHash.Signature != signatureECDSA {
				err = errors.New("tls: bad signature type for client's ECDSA certificate")
				break
			}
			ecdsaSig := new(ecdsaSignature)
			if _, err = asn1.Unmarshal(certVerify.signature, ecdsaSig); err != nil {
				break
			}
			if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
				err = errors.New("ECDSA signature contained zero or negative values")
				break
			}
			var digest []byte
			digest, _, err = hs.finishedHash.hashForClientCertificate(signatureAndHash, hs.masterSecret)
			if err != nil {
				break
			}
			if !ecdsa.Verify(key, digest, ecdsaSig.R, ecdsaSig.S) {
				err = errors.New("ECDSA verification failure")
				break
			}
		case *rsa.PublicKey:
			if signatureAndHash.Signature != signatureRSA {
				err = errors.New("tls: bad signature type for client's RSA certificate")
				break
			}
			var digest []byte
			var hashFunc crypto.Hash
			digest, hashFunc, err = hs.finishedHash.hashForClientCertificate(signatureAndHash, hs.masterSecret)
			if err != nil {
				break
			}
			err = rsa.VerifyPKCS1v15(key, hashFunc, digest, certVerify.signature)
		}
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return errors.New("could not validate signature of connection nonces: " + err.Error())
		}

		hs.writeClientHash(certVerify.marshal())
	}

	return nil
}

func (hs *serverHandshakeState) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.clientHello.random, hs.hello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)

	var clientCipher, serverCipher interface{}
	var clientHash, serverHash macFunction

	if hs.suite.aead == nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, true /* for reading */)
		clientHash = hs.suite.mac(c.vers, clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, false /* not for reading */)
		serverHash = hs.suite.mac(c.vers, serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	c.in.prepareCipherSpec(c.vers, clientCipher, clientHash)
	c.out.prepareCipherSpec(c.vers, serverCipher, serverHash)

	return nil
}

func (hs *serverHandshakeState) readFinished() error {
	c := hs.c

	c.readRecord(recordTypeChangeCipherSpec)
	if err := c.in.error(); err != nil {
		return err
	}

	if hs.hello.nextProtoNeg {
		msg, err := c.readHandshake()
		if err != nil {
			return err
		}
		nextProto, ok := msg.(*nextProtoMsg)
		if !ok {
			c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(nextProto, msg)
		}
		hs.finishedHash.Write(nextProto.marshal())
		c.clientProtocol = nextProto.proto
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	clientFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(clientFinished, msg)
	}
	c.handshakeLog.ClientFinished = clientFinished.MakeLog()

	verify := hs.finishedHash.clientSum(hs.masterSecret)
	if len(verify) != len(clientFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, clientFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: client's Finished message is incorrect")
	}

	hs.finishedHash.Write(clientFinished.marshal())
	return nil
}

func (hs *serverHandshakeState) sendSessionTicket() error {
	if !hs.hello.ticketSupported {
		return nil
	}

	c := hs.c
	m := new(newSessionTicketMsg)

	var err error
	state := sessionState{
		vers:         c.vers,
		cipherSuite:  hs.suite.id,
		masterSecret: hs.masterSecret,
		certificates: hs.certsFromClient,
	}
	m.ticket, err = c.encryptTicket(&state)
	if err != nil {
		return err
	}

	hs.finishedHash.Write(m.marshal())
	c.writeRecord(recordTypeHandshake, m.marshal())

	return nil
}

func (hs *serverHandshakeState) sendFinished() error {
	c := hs.c

	c.writeRecord(recordTypeChangeCipherSpec, []byte{1})

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.serverSum(hs.masterSecret)
	hs.finishedHash.Write(finished.marshal())
	c.writeRecord(recordTypeHandshake, finished.marshal())
	c.handshakeLog.ServerFinished = finished.MakeLog()

	c.cipherSuite = hs.suite.id

	return nil
}

// processCertsFromClient takes a chain of client certificates either from a
// Certificates message or from a sessionState and verifies them. It returns
// the public key of the leaf certificate.
func (hs *serverHandshakeState) processCertsFromClient(certificates [][]byte) (crypto.PublicKey, error) {
	c := hs.c

	hs.certsFromClient = certificates
	certs := make([]*x509.Certificate, len(certificates))
	var err error
	for i, asn1Data := range certificates {
		if certs[i], err = x509.ParseCertificate(asn1Data); err != nil {
			c.sendAlert(alertBadCertificate)
			return nil, errors.New("tls: failed to parse client certificate: " + err.Error())
		}
	}

	if c.config.ClientAuth >= VerifyClientCertIfGiven && len(certs) > 0 {
		opts := x509.VerifyOptions{
			Roots:         c.config.ClientCAs,
			CurrentTime:   c.config.time(),
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}

		chains, _, _, err := certs[0].Verify(opts)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return nil, errors.New("tls: failed to verify client's certificate: " + err.Error())
		}

		ok := false
		for _, ku := range certs[0].ExtKeyUsage {
			if ku == x509.ExtKeyUsageClientAuth {
				ok = true
				break
			}
		}
		if !ok {
			c.sendAlert(alertHandshakeFailure)
			return nil, errors.New("tls: client's certificate's extended key usage doesn't permit it to be used for client authentication")
		}

		c.verifiedChains = chains
	}

	if len(certs) > 0 {
		var pub crypto.PublicKey
		switch key := certs[0].PublicKey.(type) {
		case *ecdsa.PublicKey, *rsa.PublicKey:
			pub = key
		case *x509.AugmentedECDSA:
			pub = key.Pub
		default:
			c.sendAlert(alertUnsupportedCertificate)
			return nil, fmt.Errorf("tls: client's certificate contains an unsupported public key of type %T", certs[0].PublicKey)
		}
		c.peerCertificates = certs
		return pub, nil
	}

	return nil, nil
}

func (hs *serverHandshakeState) writeServerHash(msg []byte) {
	// writeServerHash is called before writeRecord.
	hs.writeHash(msg, 0)
}

func (hs *serverHandshakeState) writeClientHash(msg []byte) {
	// writeClientHash is called after readHandshake.
	hs.writeHash(msg, 0)
}

func (hs *serverHandshakeState) writeHash(msg []byte, seqno uint16) {
	hs.finishedHash.Write(msg)
}

// tryCipherSuite returns a cipherSuite with the given id if that cipher suite
// is acceptable to use.
func (c *Conn) tryCipherSuite(id uint16, supportedCipherSuites []uint16, version uint16, ellipticOk, ecdsaOk bool) *cipherSuite {
	for _, supported := range supportedCipherSuites {
		if id == supported {
			var candidate *cipherSuite

			for _, s := range implementedCipherSuites {
				if s.id == id {
					candidate = s
					break
				}
			}
			if candidate == nil {
				continue
			}
			// Don't select a ciphersuite which we can't
			// support for this client.
			if (candidate.flags&suiteECDHE != 0) && !ellipticOk {
				continue
			}
			if (candidate.flags&suiteECDSA != 0) != ecdsaOk {
				continue
			}
			if version < VersionTLS12 && candidate.flags&suiteTLS12 != 0 {
				continue
			}
			return candidate
		}
	}

	return nil
}

// suppVersArray is the backing array of ClientHelloInfo.SupportedVersions
var suppVersArray = [...]uint16{VersionTLS12, VersionTLS11, VersionTLS10, VersionSSL30}

func (hs *serverHandshakeState) clientHelloInfo() *ClientHelloInfo {
	if hs.cachedClientHelloInfo != nil {
		return hs.cachedClientHelloInfo
	}

	var supportedVersions []uint16
	if hs.clientHello.vers > VersionTLS12 {
		supportedVersions = suppVersArray[:]
	} else if hs.clientHello.vers >= VersionSSL30 {
		supportedVersions = suppVersArray[VersionTLS12-hs.clientHello.vers:]
	}

	signatureSchemes := make([]SignatureScheme, 0, len(hs.clientHello.signatureAndHashes))
	for _, sah := range hs.clientHello.signatureAndHashes {
		signatureSchemes = append(signatureSchemes, SignatureScheme(sah.Hash)<<8+SignatureScheme(sah.Signature))
	}

	hs.cachedClientHelloInfo = &ClientHelloInfo{
		CipherSuites:      hs.clientHello.cipherSuites,
		ServerName:        hs.clientHello.serverName,
		SupportedCurves:   hs.clientHello.supportedCurves,
		SupportedPoints:   hs.clientHello.supportedPoints,
		SignatureSchemes:  signatureSchemes,
		SupportedProtos:   hs.clientHello.alpnProtocols,
		SupportedVersions: supportedVersions,
		Conn:              hs.c.conn,
		HandshakeLog:      hs.c.handshakeLog,
	}

	return hs.cachedClientHelloInfo
}
