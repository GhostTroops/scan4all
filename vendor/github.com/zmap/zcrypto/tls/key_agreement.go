// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/zmap/zcrypto/rsa"
	"github.com/zmap/zcrypto/x509"
)

var errClientKeyExchange = errors.New("tls: invalid ClientKeyExchange message")
var errServerKeyExchange = errors.New("tls: invalid ServerKeyExchange message")

// keyAgreementAuthentication is a helper interface that specifies how
// to authenticate the ServerKeyExchange parameters.
type keyAgreementAuthentication interface {
	signParameters(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg, params []byte) (*serverKeyExchangeMsg, error)
	verifyParameters(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, params []byte, sig []byte) ([]byte, error)
}

// signedKeyAgreement signs the ServerKeyExchange parameters with the
// server's private key.
type signedKeyAgreement struct {
	version uint16
	sigType uint8
	raw     []byte
	valid   bool
	sh      SigAndHash
}

func (ka *signedKeyAgreement) signParameters(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg, params []byte) (*serverKeyExchangeMsg, error) {
	var tls12HashId uint8
	var err error
	if ka.version >= VersionTLS12 {
		if tls12HashId, err = pickTLS12HashForSignature(ka.sigType, sigAndHashes(clientHello.supportedSignatureAlgorithms), config.signatureAndHashesForServer()); err != nil {
			return nil, err
		}
		ka.sh.Hash = tls12HashId
	}
	ka.sh.Signature = ka.sigType
	hashFunc := supportedHashFunc[tls12HashId]
	digest := hashForServerKeyExchange(ka.sigType, hashFunc, ka.version, clientHello.random, hello.random, params)
	if err != nil {
		return nil, err
	}
	var sig []byte
	switch ka.sigType {
	case signatureECDSA:
		privKey, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("ECDHE ECDSA requires an ECDSA server private key")
		}
		r, s, err := ecdsa.Sign(config.rand(), privKey, digest)
		if err != nil {
			return nil, errors.New("failed to sign ECDHE parameters: " + err.Error())
		}
		sig, err = asn1.Marshal(ecdsaSignature{r, s})
		if err != nil {
			return nil, errors.New("failed to marshal ECDSA signature: " + err.Error())
		}
	case signatureRSA:
		privKey, ok := cert.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("ECDHE RSA requires a RSA server private key")
		}
		sig, err = rsa.SignPKCS1v15(config.rand(), privKey, hashFunc, digest)
		if err != nil {
			return nil, errors.New("failed to sign ECDHE parameters: " + err.Error())
		}
	default:
		return nil, errors.New("unknown ECDHE signature algorithm")
	}

	skx := new(serverKeyExchangeMsg)
	skx.digest = digest
	sigAndHashLen := 0
	if ka.version >= VersionTLS12 {
		sigAndHashLen = 2
	}
	skx.key = make([]byte, len(params)+sigAndHashLen+2+len(sig))
	copy(skx.key, params)
	k := skx.key[len(params):]
	if ka.version >= VersionTLS12 {
		k[0] = tls12HashId
		k[1] = ka.sigType
		k = k[2:]
	}
	k[0] = byte(len(sig) >> 8)
	k[1] = byte(len(sig))
	copy(k[2:], sig)
	ka.raw = sig
	ka.valid = true // We (the server) signed
	return skx, nil
}

func (ka *signedKeyAgreement) verifyParameters(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, params []byte, sig []byte) ([]byte, error) {
	if len(sig) < 2 {
		return nil, errServerKeyExchange
	}

	var tls12HashId uint8
	if ka.version >= VersionTLS12 {
		// handle SignatureAndHashAlgorithm
		var sigAndHash []uint8
		sigAndHash, sig = sig[:2], sig[2:]
		tls12HashId = sigAndHash[0]
		ka.sh.Hash = tls12HashId
		ka.sh.Signature = sigAndHash[1]
		if sigAndHash[1] != ka.sigType {
			return nil, errServerKeyExchange
		}
		if len(sig) < 2 {
			return nil, errServerKeyExchange
		}

		if !isSupportedSignatureAndHash(SigAndHash{ka.sigType, tls12HashId}, config.signatureAndHashesForClient()) {
			return nil, errors.New("tls: unsupported hash function for ServerKeyExchange")
		}
	}
	sigLen := int(sig[0])<<8 | int(sig[1])
	if sigLen+2 != len(sig) {
		return nil, errServerKeyExchange
	}
	sig = sig[2:]
	ka.raw = sig

	hashFunc := supportedHashFunc[tls12HashId]
	digest := hashForServerKeyExchange(ka.sigType, hashFunc, ka.version, clientHello.random, serverHello.random, params)
	switch ka.sigType {
	case signatureECDSA:
		augECDSA, ok := cert.PublicKey.(*x509.AugmentedECDSA)
		if !ok {
			return digest, errors.New("ECDHE ECDSA: could not covert cert.PublicKey to x509.AugmentedECDSA")
		}
		pubKey := augECDSA.Pub
		ecdsaSig := new(ecdsaSignature)
		if _, err := asn1.Unmarshal(sig, ecdsaSig); err != nil {
			return digest, err
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return digest, errors.New("ECDSA signature contained zero or negative values")
		}
		if !ecdsa.Verify(pubKey, digest, ecdsaSig.R, ecdsaSig.S) {
			return digest, errors.New("ECDSA verification failure")
		}
	case signatureRSA:
		if zPub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			if err := rsa.VerifyPKCS1v15(zPub, hashFunc, digest, sig); err != nil {
				return digest, err
			}
		} else if pubKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			if err := rsa.VerifyPKCS1v15(pubKey, hashFunc, digest, sig); err != nil {
				return digest, err
			}
		} else {
			return digest, errors.New("ECDHE RSA requires a RSA server public key")
		}
	case signatureDSA:
		pubKey, ok := cert.PublicKey.(*dsa.PublicKey)
		if !ok {
			return digest, errors.New("DSS ciphers require a DSA server public key")
		}
		dsaSig := new(dsaSignature)
		if _, err := asn1.Unmarshal(sig, dsaSig); err != nil {
			return digest, err
		}
		if dsaSig.R.Sign() <= 0 || dsaSig.S.Sign() <= 0 {
			return digest, errors.New("DSA signature contained zero or negative values")
		}
		if !dsa.Verify(pubKey, digest, dsaSig.R, dsaSig.S) {
			return digest, errors.New("DSA verification failure")
		}
	default:
		return digest, errors.New("unknown ECDHE signature algorithm")
	}
	ka.valid = true
	return digest, nil
}

// rsaKeyAgreement implements the standard TLS key agreement where the client
// encrypts the pre-master secret to the server's public key.
type rsaKeyAgreement struct {
	auth keyAgreementAuthentication

	verifyError error
}

func (ka *rsaKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	return nil, nil
}

func (ka *rsaKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	if len(ckx.ciphertext) < 2 {
		return nil, errClientKeyExchange
	}
	ciphertextLen := int(ckx.ciphertext[0])<<8 | int(ckx.ciphertext[1])
	if ciphertextLen != len(ckx.ciphertext)-2 {
		return nil, errClientKeyExchange
	}
	ciphertext := ckx.ciphertext[2:]

	priv, ok := cert.PrivateKey.(crypto.Decrypter)
	if !ok {
		return nil, errors.New("tls: certificate private key does not implement crypto.Decrypter")
	}
	// Perform constant time RSA PKCS #1 v1.5 decryption
	preMasterSecret, err := priv.Decrypt(config.rand(), ciphertext, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: 48})
	if err != nil {
		return nil, err
	}
	// We don't check the version number in the premaster secret. For one,
	// by checking it, we would leak information about the validity of the
	// encrypted pre-master secret. Secondly, it provides only a small
	// benefit against a downgrade attack and some implementations send the
	// wrong version anyway. See the discussion at the end of section
	// 7.4.7.1 of RFC 4346.
	return preMasterSecret, nil
}

func (ka *rsaKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	return errors.New("tls: unexpected ServerKeyExchange")
}

func (ka *rsaKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	preMasterSecret := make([]byte, 48)
	preMasterSecret[0] = byte(clientHello.vers >> 8)
	preMasterSecret[1] = byte(clientHello.vers)
	_, err := io.ReadFull(config.rand(), preMasterSecret[2:])
	if err != nil {
		return nil, nil, err
	}

	var encrypted []byte
	if publicKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		encrypted, err = rsa.EncryptPKCS1v15(config.rand(), publicKey, preMasterSecret)
	} else {
		return nil, nil, errClientKeyExchange
	}
	if err != nil {
		return nil, nil, err
	}
	ckx := new(clientKeyExchangeMsg)
	ckx.ciphertext = make([]byte, len(encrypted)+2)
	ckx.ciphertext[0] = byte(len(encrypted) >> 8)
	ckx.ciphertext[1] = byte(len(encrypted))
	copy(ckx.ciphertext[2:], encrypted)
	return preMasterSecret, ckx, nil
}

// sha1Hash calculates a SHA1 hash over the given byte slices.
func sha1Hash(slices [][]byte) []byte {
	hsha1 := sha1.New()
	for _, slice := range slices {
		hsha1.Write(slice)
	}
	return hsha1.Sum(nil)
}

// md5SHA1Hash implements TLS 1.0's hybrid hash function which consists of the
// concatenation of an MD5 and SHA1 hash.
func md5SHA1Hash(slices [][]byte) []byte {
	md5sha1 := make([]byte, md5.Size+sha1.Size)
	hmd5 := md5.New()
	for _, slice := range slices {
		hmd5.Write(slice)
	}
	copy(md5sha1, hmd5.Sum(nil))
	copy(md5sha1[md5.Size:], sha1Hash(slices))
	return md5sha1
}

// sha224Hash implements TLS 1.2's hash function.
func sha224Hash(slices [][]byte) []byte {
	h := crypto.SHA224.New()
	for _, slice := range slices {
		h.Write(slice)
	}
	return h.Sum(nil)
}

// sha256Hash implements TLS 1.2's hash function.
func sha256Hash(slices [][]byte) []byte {
	h := sha256.New()
	for _, slice := range slices {
		h.Write(slice)
	}
	return h.Sum(nil)
}

// sha256Hash implements TLS 1.2's hash function.
func sha384Hash(slices [][]byte) []byte {
	h := crypto.SHA384.New()
	for _, slice := range slices {
		h.Write(slice)
	}
	return h.Sum(nil)
}

// sha512Hash implements TLS 1.2's hash function.
func sha512Hash(slices [][]byte) []byte {
	h := sha512.New()
	for _, slice := range slices {
		h.Write(slice)
	}
	return h.Sum(nil)
}

// hashForServerKeyExchange hashes the given slices and returns their digest
// using the given hash function (for >= TLS 1.2) or using a default based on
// the sigType (for earlier TLS versions). For Ed25519 signatures, which don't
// do pre-hashing, it returns the concatenation of the slices.
func hashForServerKeyExchange(sigType uint8, hashFunc crypto.Hash, version uint16, slices ...[]byte) []byte {
	if sigType == signatureEd25519 {
		var signed []byte
		for _, slice := range slices {
			signed = append(signed, slice...)
		}
		return signed
	}
	if version >= VersionTLS12 {
		h := hashFunc.New()
		for _, slice := range slices {
			h.Write(slice)
		}
		digest := h.Sum(nil)
		return digest
	}
	if sigType == signatureECDSA {
		return sha1Hash(slices)
	}
	return md5SHA1Hash(slices)
}

// pickTLS12HashForSignature returns a TLS 1.2 hash identifier for signing a
// ServerKeyExchange given the signature type being used and the client's
// advertised list of supported signature and hash combinations.
func pickTLS12HashForSignature(sigType uint8, clientList, serverList []SigAndHash) (uint8, error) {
	if len(clientList) == 0 {
		// If the client didn't specify any signature_algorithms
		// extension then we can assume that it supports SHA1. See
		// http://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
		return hashSHA1, nil
	}

	for _, sigAndHash := range clientList {
		if sigAndHash.Signature != sigType {
			continue
		}
		if isSupportedSignatureAndHash(sigAndHash, serverList) {
			return sigAndHash.Hash, nil
		}
	}

	return 0, errors.New("tls: client doesn't support any common hash functions")
}

// ecdheKeyAgreement implements a TLS key agreement where the server
// generates an ephemeral EC public/private key pair and signs it. The
// pre-master secret is then calculated using ECDH. The signature may
// be ECDSA, Ed25519 or RSA.
type ecdheKeyAgreement struct {
	auth         keyAgreementAuthentication
	serverParams ecdheParameters

	version uint16
	isRSA   bool
	params  ecdheParameters

	// ckx and preMasterSecret are generated in processServerKeyExchange
	// and returned in generateClientKeyExchange.
	ckx             *clientKeyExchangeMsg
	preMasterSecret []byte

	verifyError error
}

func isTLS13OnlyKeyExchange(curveID CurveID) bool {
	switch curveID {
	case MLKEM1024, X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024:
		return true
	default:
		return false
	}
}

func (ka *ecdheKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	var curveID CurveID
	for _, c := range clientHello.supportedCurves {
		if isTLS13OnlyKeyExchange(c) {
			continue // ML-KEM hybrid group is TLS 1.3 (key_share) only.
		}
		if config.supportsCurve(c) {
			curveID = c
			break
		}
	}

	if curveID == 0 {
		return nil, errors.New("tls: no supported elliptic curves offered")
	}
	if _, ok := curveForCurveID(curveID); curveID != X25519 && !ok {
		return nil, errors.New("tls: CurvePreferences includes unsupported curve")
	}

	params, err := generateECDHEParameters(config.rand(), curveID)
	if err != nil {
		return nil, err
	}
	ka.params = params
	ka.serverParams = params.Clone()

	// See RFC 4492, Section 5.4.
	ecdhePublic := params.PublicKey()
	serverECDHEParams := make([]byte, 1+2+1+len(ecdhePublic))
	serverECDHEParams[0] = 3 // named curve
	serverECDHEParams[1] = byte(curveID >> 8)
	serverECDHEParams[2] = byte(curveID)
	serverECDHEParams[3] = byte(len(ecdhePublic))
	copy(serverECDHEParams[4:], ecdhePublic)

	priv, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("tls: certificate private key of type %T does not implement crypto.Signer", cert.PrivateKey)
	}

	var signatureAlgorithm SignatureScheme
	var sigType uint8
	var sigHash crypto.Hash
	if ka.version >= VersionTLS12 {
		signatureAlgorithm, err = selectSignatureScheme(ka.version, cert, clientHello.supportedSignatureAlgorithms)
		if err != nil {
			return nil, err
		}
		sigType, sigHash, err = typeAndHashFromSignatureScheme(signatureAlgorithm)
		if err != nil {
			return nil, err
		}
	} else {
		sigType, sigHash, err = legacyTypeAndHashFromPublicKey(priv.Public())
		if err != nil {
			return nil, err
		}
	}
	if (sigType == signaturePKCS1v15 || sigType == signatureRSAPSS) != ka.isRSA {
		return nil, errors.New("tls: certificate cannot be used with the selected cipher suite")
	}

	signed := hashForServerKeyExchange(sigType, sigHash, ka.version, clientHello.random, hello.random, serverECDHEParams)

	signOpts := crypto.SignerOpts(sigHash)
	if sigType == signatureRSAPSS {
		signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
	}
	sig, err := priv.Sign(config.rand(), signed, signOpts)
	if err != nil {
		return nil, errors.New("tls: failed to sign ECDHE parameters: " + err.Error())
	}

	skx := new(serverKeyExchangeMsg)
	sigAndHashLen := 0
	if ka.version >= VersionTLS12 {
		sigAndHashLen = 2
	}
	skx.key = make([]byte, len(serverECDHEParams)+sigAndHashLen+2+len(sig))
	copy(skx.key, serverECDHEParams)
	k := skx.key[len(serverECDHEParams):]
	if ka.version >= VersionTLS12 {
		k[0] = byte(signatureAlgorithm >> 8)
		k[1] = byte(signatureAlgorithm)
		k = k[2:]
	}
	k[0] = byte(len(sig) >> 8)
	k[1] = byte(len(sig))
	copy(k[2:], sig)

	return skx, nil
}

func (ka *ecdheKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	if len(ckx.ciphertext) == 0 || int(ckx.ciphertext[0]) != len(ckx.ciphertext)-1 {
		return nil, errClientKeyExchange
	}

	preMasterSecret := ka.params.SharedKey(ckx.ciphertext[1:])
	if preMasterSecret == nil {
		return nil, errClientKeyExchange
	}

	// This part is solely for logging purposes. Later in MakeLog(), we only have access to ka.params
	// for the client key exchange parameters. We need to store the client's public key here
	// to make the log later. The Go TLS library doesn't store the parsed client public key anywhere.
	ka.params = nil
	if ka.serverParams.CurveID() == X25519 {
		ka.params = &x25519Parameters{publicKey: ckx.ciphertext[1:]}
	} else {
		curve, ok := curveForCurveID(ka.serverParams.CurveID())
		if ok {
			x, y := elliptic.Unmarshal(curve, ckx.ciphertext[1:])
			ka.params = &nistParameters{x: x, y: y, curveID: ka.serverParams.CurveID()}
		}
	}

	return preMasterSecret, nil
}

func (ka *ecdheKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	if len(skx.key) < 4 {
		return errServerKeyExchange
	}
	if skx.key[0] != 3 { // named curve
		return errors.New("tls: server selected unsupported curve")
	}
	curveID := CurveID(skx.key[1])<<8 | CurveID(skx.key[2])

	publicLen := int(skx.key[3])
	if publicLen+4 > len(skx.key) {
		return errServerKeyExchange
	}
	serverECDHEParams := skx.key[:4+publicLen]
	publicKey := serverECDHEParams[4:]

	sig := skx.key[4+publicLen:]
	if len(sig) < 2 {
		return errServerKeyExchange
	}

	if curve, ok := curveForCurveID(curveID); curveID != X25519 && !ok {
		return errors.New("tls: server selected unsupported curve")
	} else {
		if curveID == X25519 {
			ka.serverParams = &x25519Parameters{publicKey: publicKey}
		} else {
			x, y := elliptic.Unmarshal(curve, publicKey)
			ka.serverParams = &nistParameters{x: x, y: y, curveID: curveID}
		}
	}

	params, err := generateECDHEParameters(config.rand(), curveID)
	if err != nil {
		return err
	}
	ka.params = params

	ka.preMasterSecret = params.SharedKey(publicKey)
	if ka.preMasterSecret == nil {
		return errServerKeyExchange
	}

	ourPublicKey := params.PublicKey()
	ka.ckx = new(clientKeyExchangeMsg)
	ka.ckx.ciphertext = make([]byte, 1+len(ourPublicKey))
	ka.ckx.ciphertext[0] = byte(len(ourPublicKey))
	copy(ka.ckx.ciphertext[1:], ourPublicKey)

	var sigType uint8
	var sigHash crypto.Hash
	if ka.version >= VersionTLS12 {
		signatureAlgorithm := SignatureScheme(sig[0])<<8 | SignatureScheme(sig[1])
		sig = sig[2:]
		if len(sig) < 2 {
			return errServerKeyExchange
		}

		if !isSupportedSignatureAlgorithm(signatureAlgorithm, clientHello.supportedSignatureAlgorithms) {
			return errors.New("tls: certificate used with invalid signature algorithm")
		}
		sigType, sigHash, err = typeAndHashFromSignatureScheme(signatureAlgorithm)
		if err != nil {
			return err
		}
	} else {
		sigType, sigHash, err = legacyTypeAndHashFromPublicKey(cert.PublicKey)
		if err != nil {
			return err
		}
	}
	if (sigType == signaturePKCS1v15 || sigType == signatureRSAPSS) != ka.isRSA {
		return errServerKeyExchange
	}

	sigLen := int(sig[0])<<8 | int(sig[1])
	if sigLen+2 != len(sig) {
		return errServerKeyExchange
	}
	sig = sig[2:]

	signed := hashForServerKeyExchange(sigType, sigHash, ka.version, clientHello.random, serverHello.random, serverECDHEParams)
	ka.verifyError = verifyHandshakeSignature(sigType, cert.PublicKey, sigHash, signed, sig)

	// For logging purposes
	skx.digest = signed
	switch auth := ka.auth.(type) {
	case *signedKeyAgreement:
		auth.raw = sig
		auth.valid = ka.verifyError == nil
		auth.sh.Signature = sigType
		auth.sh.Hash = uint8(sigHash)
	default:
		break
	}

	if ka.verifyError != nil {
		return errors.New("tls: invalid signature by the server certificate: " + ka.verifyError.Error())
	}
	return nil
}

func (ka *ecdheKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.ckx == nil {
		return nil, nil, errors.New("tls: missing ServerKeyExchange message")
	}

	return ka.preMasterSecret, ka.ckx, nil
}

// dheRSAKeyAgreement implements a TLS key agreement where the server generates
// an ephemeral Diffie-Hellman public/private key pair and signs it. The
// pre-master secret is then calculated using Diffie-Hellman.
type dheKeyAgreement struct {
	auth        keyAgreementAuthentication
	p, g        *big.Int
	yTheirs     *big.Int
	yOurs       *big.Int
	xOurs       *big.Int
	yServer     *big.Int
	yClient     *big.Int
	verifyError error
}

func (ka *dheKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	var q *big.Int
	// 2048-bit MODP Group with 256-bit Prime Order Subgroup (RFC
	// 5114, Section 2.3)
	// TODO: Take a prime in the config
	ka.p, _ = new(big.Int).SetString("87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597", 16)
	ka.g, _ = new(big.Int).SetString("3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659", 16)
	q, _ = new(big.Int).SetString("8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3", 16)

	var err error
	ka.xOurs, err = rand.Int(config.rand(), q)
	if err != nil {
		return nil, err
	}
	yOurs := new(big.Int).Exp(ka.g, ka.xOurs, ka.p)
	ka.yOurs = yOurs
	ka.yServer = new(big.Int).Set(yOurs)

	// http://tools.ietf.org/html/rfc5246#section-7.4.3
	pBytes := ka.p.Bytes()
	gBytes := ka.g.Bytes()
	yBytes := yOurs.Bytes()
	serverDHParams := make([]byte, 0, 2+len(pBytes)+2+len(gBytes)+2+len(yBytes))
	serverDHParams = append(serverDHParams, byte(len(pBytes)>>8), byte(len(pBytes)))
	serverDHParams = append(serverDHParams, pBytes...)
	serverDHParams = append(serverDHParams, byte(len(gBytes)>>8), byte(len(gBytes)))
	serverDHParams = append(serverDHParams, gBytes...)
	serverDHParams = append(serverDHParams, byte(len(yBytes)>>8), byte(len(yBytes)))
	serverDHParams = append(serverDHParams, yBytes...)

	return ka.auth.signParameters(config, cert, clientHello, hello, serverDHParams)
}

func (ka *dheKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	if len(ckx.ciphertext) < 2 {
		return nil, errClientKeyExchange
	}
	yLen := (int(ckx.ciphertext[0]) << 8) | int(ckx.ciphertext[1])
	if yLen != len(ckx.ciphertext)-2 {
		return nil, errClientKeyExchange
	}
	yTheirs := new(big.Int).SetBytes(ckx.ciphertext[2:])
	ka.yClient = new(big.Int).Set(yTheirs)
	if yTheirs.Sign() <= 0 || yTheirs.Cmp(ka.p) >= 0 {
		return nil, errClientKeyExchange
	}
	return new(big.Int).Exp(yTheirs, ka.xOurs, ka.p).Bytes(), nil
}

func (ka *dheKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	// Read dh_p
	k := skx.key
	if len(k) < 2 {
		return errServerKeyExchange
	}
	pLen := (int(k[0]) << 8) | int(k[1])
	k = k[2:]
	if len(k) < pLen {
		return errServerKeyExchange
	}
	ka.p = new(big.Int).SetBytes(k[:pLen])
	k = k[pLen:]

	// Read dh_g
	if len(k) < 2 {
		return errServerKeyExchange
	}
	gLen := (int(k[0]) << 8) | int(k[1])
	k = k[2:]
	if len(k) < gLen {
		return errServerKeyExchange
	}
	ka.g = new(big.Int).SetBytes(k[:gLen])
	k = k[gLen:]

	// Read dh_Ys
	if len(k) < 2 {
		return errServerKeyExchange
	}
	yLen := (int(k[0]) << 8) | int(k[1])
	k = k[2:]
	if len(k) < yLen {
		return errServerKeyExchange
	}
	ka.yTheirs = new(big.Int).SetBytes(k[:yLen])
	ka.yServer = new(big.Int).Set(ka.yTheirs)
	k = k[yLen:]
	if ka.yTheirs.Sign() <= 0 || ka.yTheirs.Cmp(ka.p) >= 0 {
		return errServerKeyExchange
	}

	sig := k
	serverDHParams := skx.key[:len(skx.key)-len(sig)]
	skx.digest, ka.verifyError = ka.auth.verifyParameters(config, clientHello, serverHello, cert, serverDHParams, sig)
	if config.InsecureSkipVerify {
		return nil
	}
	return ka.verifyError
}

func (ka *dheKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.p == nil || ka.g == nil || ka.yTheirs == nil {
		return nil, nil, errors.New("missing ServerKeyExchange message")
	}

	xOurs, err := rand.Int(config.rand(), ka.p)
	if err != nil {
		return nil, nil, err
	}
	preMasterSecret := new(big.Int).Exp(ka.yTheirs, xOurs, ka.p).Bytes()

	yOurs := new(big.Int).Exp(ka.g, xOurs, ka.p)
	ka.yOurs = yOurs
	ka.xOurs = xOurs
	ka.yClient = new(big.Int).Set(yOurs)
	yBytes := yOurs.Bytes()
	ckx := new(clientKeyExchangeMsg)
	ckx.ciphertext = make([]byte, 2+len(yBytes))
	ckx.ciphertext[0] = byte(len(yBytes) >> 8)
	ckx.ciphertext[1] = byte(len(yBytes))
	copy(ckx.ciphertext[2:], yBytes)

	return preMasterSecret, ckx, nil
}
