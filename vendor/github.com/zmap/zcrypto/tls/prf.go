// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

// Split a premaster secret in two as specified in RFC 4346, section 5.
func splitPreMasterSecret(secret []byte) (s1, s2 []byte) {
	s1 = secret[0 : (len(secret)+1)/2]
	s2 = secret[len(secret)/2:]
	return
}

// pHash implements the P_hash function, as defined in RFC 4346, section 5.
func pHash(result, secret, seed []byte, hash func() hash.Hash) {
	h := hmac.New(hash, secret)
	h.Write(seed)
	a := h.Sum(nil)

	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		todo := len(b)
		if j+todo > len(result) {
			todo = len(result) - j
		}
		copy(result[j:j+todo], b)
		j += todo

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}

// prf10 implements the TLS 1.0 pseudo-random function, as defined in RFC 2246, section 5.
func prf10(result, secret, label, seed []byte) {
	hashSHA1 := sha1.New
	hashMD5 := md5.New

	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)

	s1, s2 := splitPreMasterSecret(secret)
	pHash(result, s1, labelAndSeed, hashMD5)
	result2 := make([]byte, len(result))
	pHash(result2, s2, labelAndSeed, hashSHA1)

	for i, b := range result2 {
		result[i] ^= b
	}
}

// prf12 implements the TLS 1.2 pseudo-random function, as defined in RFC 5246, section 5.
func prf12(hashFunc func() hash.Hash) func(result, secret, label, seed []byte) {
	return func(result, secret, label, seed []byte) {
		labelAndSeed := make([]byte, len(label)+len(seed))
		copy(labelAndSeed, label)
		copy(labelAndSeed[len(label):], seed)

		pHash(result, secret, labelAndSeed, hashFunc)
	}
}

// prf30 implements the SSL 3.0 pseudo-random function, as defined in
// www.mozilla.org/projects/security/pki/nss/ssl/draft302.txt section 6.
func prf30(result, secret, label, seed []byte) {
	hashSHA1 := sha1.New()
	hashMD5 := md5.New()

	done := 0
	i := 0
	// RFC5246 section 6.3 says that the largest PRF output needed is 128
	// bytes. Since no more ciphersuites will be added to SSLv3, this will
	// remain true. Each iteration gives us 16 bytes so 10 iterations will
	// be sufficient.
	var b [11]byte
	for done < len(result) {
		for j := 0; j <= i; j++ {
			b[j] = 'A' + byte(i)
		}

		hashSHA1.Reset()
		hashSHA1.Write(b[:i+1])
		hashSHA1.Write(secret)
		hashSHA1.Write(seed)
		digest := hashSHA1.Sum(nil)

		hashMD5.Reset()
		hashMD5.Write(secret)
		hashMD5.Write(digest)

		done += copy(result[done:], hashMD5.Sum(nil))
		i++
	}
}

func exportPRF30(result, secret, label, seed []byte) {
	hash := md5.New()
	hash.Write(secret)
	hash.Write(seed)
	copy(result, hash.Sum(nil))
}

const (
	tlsRandomLength      = 32 // Length of a random nonce in TLS 1.1.
	masterSecretLength   = 48 // Length of a master secret in TLS 1.1.
	finishedVerifyLength = 12 // Length of verify_data in a Finished message.
)

var masterSecretLabel = []byte("master secret")
var extendedMasterSecretLabel = []byte("extended master secret")
var keyExpansionLabel = []byte("key expansion")
var clientFinishedLabel = []byte("client finished")
var serverFinishedLabel = []byte("server finished")
var clientFinalKeyLabel = []byte("client write key")
var serverFinalKeyLabel = []byte("server write key")
var finalIVLabel = []byte("IV block")

func prfForVersion(version uint16, suite *cipherSuite) func(result, secret, label, seed []byte) {
	switch version {
	case VersionSSL30:
		return prf30
	case VersionTLS10, VersionTLS11:
		return prf10
	case VersionTLS12:
		if suite.flags&suiteSHA384 != 0 {
			return prf12(sha512.New384)
		}
		return prf12(sha256.New)
	default:
		panic("unknown version")
	}
}

// masterFromPreMasterSecret generates the master secret from the pre-master
// secret. See http://tools.ietf.org/html/rfc5246#section-8.1
func masterFromPreMasterSecret(version uint16, suite *cipherSuite, preMasterSecret, clientRandom, serverRandom []byte) []byte {
	seed := make([]byte, len(clientRandom)+len(serverRandom))
	copy(seed[0:len(clientRandom)], clientRandom)
	copy(seed[len(clientRandom):], serverRandom)
	masterSecret := make([]byte, masterSecretLength)
	prfForVersion(version, suite)(masterSecret, preMasterSecret, masterSecretLabel, seed[0:])
	return masterSecret
}

// extendedMasterFromPreMasterSecret generates the master secret from the
// pre-master secret when the Triple Handshake fix is in effect. See
// https://tools.ietf.org/html/draft-ietf-tls-session-hash-01
func extendedMasterFromPreMasterSecret(version uint16, suite *cipherSuite, preMasterSecret []byte, h finishedHash) []byte {
	masterSecret := make([]byte, masterSecretLength)
	prfForVersion(version, suite)(masterSecret, preMasterSecret, extendedMasterSecretLabel, h.Sum())
	return masterSecret
}

// keysFromMasterSecret generates the connection keys from the master
// secret, given the lengths of the MAC key, cipher key and IV, as defined in
// RFC 2246, section 6.3.
func keysFromMasterSecret(version uint16, suite *cipherSuite, masterSecret, clientRandom, serverRandom []byte, macLen, keyLen, ivLen int) (clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV []byte) {
	if suite.flags&suiteExport > 0 {
		return exportKeysFromMasterSecret(version, suite, masterSecret, clientRandom, serverRandom, macLen, keyLen, ivLen)
	}
	var seed [tlsRandomLength * 2]byte
	copy(seed[0:len(clientRandom)], serverRandom)
	copy(seed[len(serverRandom):], clientRandom)

	n := 2*macLen + 2*keyLen + 2*ivLen
	keyMaterial := make([]byte, n)
	prfForVersion(version, suite)(keyMaterial, masterSecret, keyExpansionLabel, seed[0:])
	clientMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	serverMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	clientKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	serverKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	clientIV = keyMaterial[:ivLen]
	keyMaterial = keyMaterial[ivLen:]
	serverIV = keyMaterial[:ivLen]
	return
}

// The crypto wars must have been the worst
func exportKeysFromMasterSecret30(version uint16, suite *cipherSuite, masterSecret, clientRandom, serverRandom []byte, macLen, keyLen, ivLen int) (clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV []byte) {
	var seed [tlsRandomLength * 2]byte
	copy(seed[0:len(clientRandom)], serverRandom)
	copy(seed[len(serverRandom):], clientRandom)
	n := 2*macLen + 2*keyLen
	keyMaterial := make([]byte, n)
	prf30(keyMaterial, masterSecret, keyExpansionLabel, seed[0:])
	clientMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	serverMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	clientKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	serverKey = keyMaterial[:keyLen]
	var exportSeed [tlsRandomLength * 2]byte
	copy(exportSeed[0:len(serverRandom)], clientRandom)
	copy(exportSeed[len(clientRandom):], serverRandom)
	expandedKeyLen := suite.expandedKeyLen
	finalKeyBlock := make([]byte, 2*expandedKeyLen)
	exportPRF30(finalKeyBlock[:expandedKeyLen], clientKey, clientFinalKeyLabel, exportSeed[0:])
	clientKey = finalKeyBlock[:expandedKeyLen]
	finalKeyBlock = finalKeyBlock[expandedKeyLen:]
	exportPRF30(finalKeyBlock[:expandedKeyLen], serverKey, serverFinalKeyLabel, seed[0:])
	serverKey = finalKeyBlock[:expandedKeyLen]
	ivBlock := make([]byte, 2*ivLen)
	clientIV = ivBlock[:ivLen]
	exportPRF30(clientIV, []byte{}, finalIVLabel, exportSeed[0:])
	ivBlock = ivBlock[ivLen:]
	serverIV = ivBlock[:ivLen]
	exportPRF30(serverIV, []byte{}, finalIVLabel, seed[0:])
	return
}

// If a cryptographer kills me in the night, let it be known I was sorry
func exportKeysFromMasterSecretTLS(version uint16, suite *cipherSuite, masterSecret, clientRandom, serverRandom []byte, macLen, keyLen, ivLen int) (clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV []byte) {
	var seed [tlsRandomLength * 2]byte
	copy(seed[0:len(clientRandom)], serverRandom)
	copy(seed[len(serverRandom):], clientRandom)
	n := 2*macLen + 2*keyLen
	keyMaterial := make([]byte, n)
	prf := prfForVersion(version, suite)
	prf(keyMaterial, masterSecret, keyExpansionLabel, seed[0:])
	clientMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	serverMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	clientKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	serverKey = keyMaterial[:keyLen]
	expandedKeyLen := suite.expandedKeyLen
	finalKeyBlock := make([]byte, 2*expandedKeyLen)
	var exportSeed [tlsRandomLength * 2]byte
	copy(exportSeed[0:len(serverRandom)], clientRandom)
	copy(exportSeed[len(clientRandom):], serverRandom)
	prf(finalKeyBlock[:expandedKeyLen], clientKey, clientFinalKeyLabel, exportSeed[0:])
	clientKey = finalKeyBlock[:expandedKeyLen]
	finalKeyBlock = finalKeyBlock[expandedKeyLen:]
	prf(finalKeyBlock[:expandedKeyLen], serverKey, serverFinalKeyLabel, exportSeed[0:])
	serverKey = finalKeyBlock[:expandedKeyLen]
	ivBlock := make([]byte, 2*ivLen)
	prf(ivBlock, []byte{}, finalIVLabel, exportSeed[0:])
	clientIV = ivBlock[:ivLen]
	ivBlock = ivBlock[ivLen:]
	serverIV = ivBlock[:ivLen]
	return
}

func exportKeysFromMasterSecret(version uint16, suite *cipherSuite, masterSecret, clientRandom, serverRandom []byte, macLen, keyLen, ivLen int) (clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV []byte) {
	switch version {
	case VersionSSL30:
		return exportKeysFromMasterSecret30(version, suite, masterSecret, clientRandom, serverRandom, macLen, keyLen, ivLen)
	case VersionTLS10, VersionTLS11, VersionTLS12:
		return exportKeysFromMasterSecretTLS(version, suite, masterSecret, clientRandom, serverRandom, macLen, keyLen, ivLen)
	default:
		panic("unknown version")
	}
}

// lookupTLSHash looks up the corresponding crypto.Hash for a given
// TLS hash identifier.
func lookupTLSHash(hash uint8) (crypto.Hash, error) {
	switch hash {
	case hashMD5:
		return crypto.MD5, nil
	case hashSHA1:
		return crypto.SHA1, nil
	case hashSHA224:
		return crypto.SHA224, nil
	case hashSHA256:
		return crypto.SHA256, nil
	case hashSHA384:
		return crypto.SHA384, nil
	case hashSHA512:
		return crypto.SHA512, nil
	default:
		return 0, errors.New("tls: unsupported hash algorithm")
	}
}

func newFinishedHash(version uint16, cipherSuite *cipherSuite) finishedHash {
	if version >= VersionTLS12 {
		newHash := sha256.New
		if cipherSuite != nil && cipherSuite.flags&suiteSHA384 != 0 {
			newHash = sha512.New384
		}

		return finishedHash{newHash(), newHash(), nil, nil, []byte{}, version, prf12(newHash)}
	}
	return finishedHash{sha1.New(), sha1.New(), md5.New(), md5.New(), []byte{}, version, prf10}
}

// A finishedHash calculates the hash of a set of handshake messages suitable
// for including in a Finished message.
type finishedHash struct {
	client hash.Hash
	server hash.Hash

	// Prior to TLS 1.2, an additional MD5 hash is required.
	clientMD5 hash.Hash
	serverMD5 hash.Hash

	// In TLS 1.2 (and SSL 3 for implementation convenience), a
	// full buffer is required.
	buffer []byte

	version uint16
	prf     func(result, secret, label, seed []byte)
}

func (h *finishedHash) Write(msg []byte) (n int, err error) {
	h.client.Write(msg)
	h.server.Write(msg)

	if h.version < VersionTLS12 {
		h.clientMD5.Write(msg)
		h.serverMD5.Write(msg)
	}

	if h.buffer != nil {
		h.buffer = append(h.buffer, msg...)
	}

	return len(msg), nil
}

func (h finishedHash) Sum() []byte {
	if h.version >= VersionTLS12 {
		return h.client.Sum(nil)
	}

	out := make([]byte, 0, md5.Size+sha1.Size)
	out = h.clientMD5.Sum(out)
	return h.client.Sum(out)
}

// finishedSum30 calculates the contents of the verify_data member of a SSLv3
// Finished message given the MD5 and SHA1 hashes of a set of handshake
// messages.
func finishedSum30(md5, sha1 hash.Hash, masterSecret []byte, magic []byte) []byte {
	md5.Write(magic)
	md5.Write(masterSecret)
	md5.Write(ssl30Pad1[:])
	md5Digest := md5.Sum(nil)

	md5.Reset()
	md5.Write(masterSecret)
	md5.Write(ssl30Pad2[:])
	md5.Write(md5Digest)
	md5Digest = md5.Sum(nil)

	sha1.Write(magic)
	sha1.Write(masterSecret)
	sha1.Write(ssl30Pad1[:40])
	sha1Digest := sha1.Sum(nil)

	sha1.Reset()
	sha1.Write(masterSecret)
	sha1.Write(ssl30Pad2[:40])
	sha1.Write(sha1Digest)
	sha1Digest = sha1.Sum(nil)

	ret := make([]byte, len(md5Digest)+len(sha1Digest))
	copy(ret, md5Digest)
	copy(ret[len(md5Digest):], sha1Digest)
	return ret
}

var ssl3ClientFinishedMagic = [4]byte{0x43, 0x4c, 0x4e, 0x54}
var ssl3ServerFinishedMagic = [4]byte{0x53, 0x52, 0x56, 0x52}

// clientSum returns the contents of the verify_data member of a client's
// Finished message.
func (h finishedHash) clientSum(masterSecret []byte) []byte {
	if h.version == VersionSSL30 {
		return finishedSum30(h.clientMD5, h.client, masterSecret, ssl3ClientFinishedMagic[:])
	}

	out := make([]byte, finishedVerifyLength)
	h.prf(out, masterSecret, clientFinishedLabel, h.Sum())
	return out
}

// serverSum returns the contents of the verify_data member of a server's
// Finished message.
func (h finishedHash) serverSum(masterSecret []byte) []byte {
	if h.version == VersionSSL30 {
		return finishedSum30(h.serverMD5, h.server, masterSecret, ssl3ServerFinishedMagic[:])
	}

	out := make([]byte, finishedVerifyLength)
	h.prf(out, masterSecret, serverFinishedLabel, h.Sum())
	return out
}

// selectClientCertSignatureAlgorithm returns a SigAndHash to sign a
// client's CertificateVerify with, or an error if none can be found.
func (h finishedHash) selectClientCertSignatureAlgorithm(serverList, clientList []SigAndHash, sigType uint8) (SigAndHash, error) {
	if h.version < VersionTLS12 {
		// Nothing to negotiate before TLS 1.2.
		return SigAndHash{Signature: sigType}, nil
	}

	for _, v := range serverList {
		if v.Signature == sigType && isSupportedSignatureAndHash(v, clientList) {
			return v, nil
		}
	}
	return SigAndHash{}, errors.New("tls: no supported signature algorithm found for signing client certificate")
}

// hashForClientCertificate returns a digest, hash function, and TLS 1.2 hash
// id suitable for signing by a TLS client certificate.
func (h finishedHash) hashForClientCertificate(signatureAndHash SigAndHash, masterSecret []byte) ([]byte, crypto.Hash, error) {
	if h.version == VersionSSL30 {
		if signatureAndHash.Signature != signatureRSA {
			return nil, 0, errors.New("tls: unsupported signature type for client certificate")
		}

		md5Hash := md5.New()
		md5Hash.Write(h.buffer)
		sha1Hash := sha1.New()
		sha1Hash.Write(h.buffer)
		return finishedSum30(md5Hash, sha1Hash, masterSecret, nil), crypto.MD5SHA1, nil
	}
	if h.version >= VersionTLS12 {
		hashAlg, err := lookupTLSHash(signatureAndHash.Hash)
		if err != nil {
			return nil, 0, err
		}
		hash := hashAlg.New()
		hash.Write(h.buffer)
		return hash.Sum(nil), hashAlg, nil
	}
	if signatureAndHash.Signature == signatureECDSA {
		return h.server.Sum(nil), crypto.SHA1, nil
	}

	return h.Sum(), crypto.MD5SHA1, nil
}
