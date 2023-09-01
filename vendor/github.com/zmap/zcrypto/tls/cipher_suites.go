// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"github.com/zmap/rc2"
	"github.com/zmap/zcrypto/x509"
	"golang.org/x/crypto/chacha20poly1305"
)

// a keyAgreement implements the client and server side of a TLS key agreement
// protocol by generating and processing key exchange messages.
type keyAgreement interface {
	// On the server side, the first two methods are called in order.

	// In the case that the key agreement protocol doesn't use a
	// ServerKeyExchange message, generateServerKeyExchange can return nil,
	// nil.
	generateServerKeyExchange(*Config, *Certificate, *clientHelloMsg, *serverHelloMsg) (*serverKeyExchangeMsg, error)
	processClientKeyExchange(*Config, *Certificate, *clientKeyExchangeMsg) ([]byte, error)

	// On the client side, the next two methods are called in order.

	// This method may not be called if the server doesn't send a
	// ServerKeyExchange message.
	processServerKeyExchange(*Config, *clientHelloMsg, *serverHelloMsg, *x509.Certificate, *serverKeyExchangeMsg) error
	generateClientKeyExchange(*Config, *clientHelloMsg, *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error)
}

const (
	// suiteECDH indicates that the cipher suite involves elliptic curve
	// Diffie-Hellman. This means that it should only be selected when the
	// client indicates that it supports ECC with a curve and point format
	// that we're happy with.
	suiteECDHE = 1 << iota
	// suiteECDSA indicates that the cipher suite involves an ECDSA
	// signature and therefore may only be selected when the server's
	// certificate is ECDSA. If this is not set then the cipher suite is
	// RSA based.
	suiteECDSA
	// suiteTLS12 indicates that the cipher suite should only be advertised
	// and accepted when using TLS 1.2.
	suiteTLS12

	// suiteSHA384 indicates that the cipher suite uses SHA384 as the
	// handshake hash.
	suiteSHA384

	// suiteNoDTLS indicates that the cipher suite cannot be used
	// in DTLS.
	suiteNoDTLS

	// suitePSK indicates that the cipher suite authenticates with
	// a pre-shared key rather than a server private key.
	suitePSK

	// suiteExport indicates that the cipher suite is an export suite
	suiteExport

	// suiteAnon indicates the cipher suite is anonymous
	suiteAnon

	// suiteDSS indicates the cipher suite uses DSS signatures and requires a
	// DSA server key
	suiteDSS
)

// A cipherSuite is a specific combination of key agreement, cipher and MAC
// function. All cipher suites currently assume RSA key agreement.
type cipherSuite struct {
	id uint16
	// the lengths, in bytes, of the key material needed for each component.
	keyLen int
	macLen int
	ivLen  int

	// used by export ciphers
	expandedKeyLen int

	ka func(version uint16) keyAgreement
	// flags is a bitmask of the suite* values, above.
	flags  int
	cipher func(key, iv []byte, isRead bool) interface{}
	mac    func(version uint16, macKey []byte) macFunction
	aead   func(key, fixedNonce []byte) tlsAead
}

type tlsAead interface {
	cipher.AEAD
	explicitNonce() bool
}

// Incidences of unsupported cipher-suites are annotated in-line with comments
// The following guidelines should be noted:
//   - DSS Suites: certificates are not supported (Certificate)
//   - PSK Suites: Not supported/implemented (Symmetric Key)
//   - Non-ephemeral, Anonymous DH: Not supported/implemented (Kex)
var implementedCipherSuites = []*cipherSuite{
	{TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, 32, ecdheECDSAKA, suiteECDHE | suiteECDSA | suiteTLS12, nil, nil, aeadCHACHA20POLY1305},
	{TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, 32, ecdheRSAKA, suiteECDHE | suiteTLS12, nil, nil, aeadCHACHA20POLY1305},
	{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, 16, ecdheRSAKA, suiteECDHE | suiteTLS12, nil, nil, aeadAESGCM},
	{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, 16, ecdheECDSAKA, suiteECDHE | suiteECDSA | suiteTLS12, nil, nil, aeadAESGCM},
	{TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, 32, ecdheRSAKA, suiteECDHE | suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, 32, ecdheECDSAKA, suiteECDHE | suiteECDSA | suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{TLS_ECDHE_RSA_WITH_RC4_128_SHA, 16, 20, 0, 16, ecdheRSAKA, suiteECDHE | suiteNoDTLS, cipherRC4, macSHA1, nil},
	{TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, 16, 20, 0, 16, ecdheECDSAKA, suiteECDHE | suiteECDSA | suiteNoDTLS, cipherRC4, macSHA1, nil},
	{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, 16, ecdheRSAKA, suiteECDHE | suiteTLS12, cipherAES, macSHA256, nil},
	{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, 16, ecdheECDSAKA, suiteECDHE | suiteECDSA | suiteTLS12, cipherAES, macSHA256, nil},
	{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, 16, ecdheRSAKA, suiteECDHE, cipherAES, macSHA1, nil},
	{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, 16, 20, 16, 16, ecdheECDSAKA, suiteECDHE | suiteECDSA, cipherAES, macSHA1, nil},
	{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, 32, ecdheRSAKA, suiteECDHE | suiteTLS12 | suiteSHA384, cipherAES, macSHA384, nil},
	{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, 32, ecdheECDSAKA, suiteECDHE | suiteECDSA | suiteTLS12 | suiteSHA384, cipherAES, macSHA384, nil},
	{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, 32, ecdheRSAKA, suiteECDHE, cipherAES, macSHA1, nil},
	{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, 32, 20, 16, 32, ecdheECDSAKA, suiteECDHE | suiteECDSA, cipherAES, macSHA1, nil},
	{TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, 32, dheRSAKA, suiteTLS12, nil, nil, aeadCHACHA20POLY1305},
	{TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, 16, dheRSAKA, suiteTLS12, nil, nil, aeadAESGCM},
	{TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, 32, dheRSAKA, suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, 16, dheRSAKA, suiteTLS12, cipherAES, macSHA256, nil},
	{TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, 32, 32, 16, 32, dheRSAKA, suiteTLS12, cipherAES, macSHA256, nil},
	{TLS_DHE_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, 16, dheRSAKA, 0, cipherAES, macSHA1, nil},
	{TLS_DHE_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, 32, dheRSAKA, 0, cipherAES, macSHA1, nil},
	{TLS_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, 16, rsaKA, suiteTLS12, nil, nil, aeadAESGCM},
	{TLS_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, 32, rsaKA, suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{TLS_RSA_WITH_RC4_128_SHA, 16, 20, 0, 16, rsaKA, suiteNoDTLS, cipherRC4, macSHA1, nil},
	{TLS_RSA_WITH_RC4_128_MD5, 16, 16, 0, 16, rsaKA, suiteNoDTLS, cipherRC4, macMD5, nil},
	{TLS_RSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, 16, rsaKA, suiteTLS12, cipherAES, macSHA256, nil},
	{TLS_RSA_WITH_AES_256_CBC_SHA256, 32, 32, 16, 32, rsaKA, suiteTLS12, cipherAES, macSHA256, nil},
	{TLS_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, 16, rsaKA, 0, cipherAES, macSHA1, nil},
	{TLS_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, 32, rsaKA, 0, cipherAES, macSHA1, nil},
	{TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, 24, ecdheRSAKA, suiteECDHE, cipher3DES, macSHA1, nil},
	{TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, 24, dheRSAKA, 0, cipher3DES, macSHA1, nil},
	{TLS_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, 24, rsaKA, 0, cipher3DES, macSHA1, nil},
	// WARN: PSK: Not supported/implemented
	//{TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256, 16, 0, 4, ecdhePSKKA, suiteECDHE | suiteTLS12 | suitePSK, nil, nil, aeadAESGCM},
	//{TLS_PSK_WITH_RC4_128_SHA, 16, 20, 0, pskKA, suiteNoDTLS | suitePSK, cipherRC4, macSHA1, nil},
	//{TLS_PSK_WITH_AES_128_CBC_SHA, 16, 20, 16, pskKA, suitePSK, cipherAES, macSHA1, nil},
	//{TLS_PSK_WITH_AES_256_CBC_SHA, 32, 20, 16, pskKA, suitePSK, cipherAES, macSHA1, nil},
	//{TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA, 16, 20, 16, ecdhePSKKA, suiteECDHE | suitePSK, cipherAES, macSHA1, nil},
	//{TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA, 32, 20, 16, ecdhePSKKA, suiteECDHE | suitePSK, cipherAES, macSHA1, nil},
	{TLS_RSA_EXPORT_WITH_RC4_40_MD5, 5, 16, 0, 16, rsaEphemeralKA, suiteExport, cipherRC4, macMD5, nil},
	{TLS_RSA_EXPORT_WITH_DES40_CBC_SHA, 5, 20, 8, 8, rsaEphemeralKA, suiteExport, cipherDES, macSHA1, nil},
	{TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5, 5, 16, 8, 16, rsaEphemeralKA, suiteExport, cipherRC2, macMD5, nil},
	{TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA, 5, 20, 8, 8, dheRSAKA, suiteExport, cipherDES, macSHA1, nil},
	// WARN: DSS: Certificate not supported/implemented
	{TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA, 5, 20, 8, 8, dheDSSKA, suiteExport | suiteDSS, cipherDES, macSHA1, nil},
	// WARN: Non-ephemeral, Anonymous DH: Not supported/implemented
	{TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA, 5, 20, 8, 8, dhAnonKA, suiteExport | suiteAnon, cipherDES, macSHA1, nil},
	{TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5, 5, 16, 0, 16, dhAnonKA, suiteExport | suiteAnon, cipherRC4, macMD5, nil},
	// WARN DSS: Certificate not supported/implemented
	{TLS_DHE_DSS_WITH_AES_128_CBC_SHA, 16, 20, 16, 16, dheDSSKA, suiteDSS, cipherAES, macSHA1, nil},
	{TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, 24, ecdheECDSAKA, suiteECDHE | suiteECDSA, cipher3DES, macSHA1, nil},
	// WARN: DSS: Certificate not supported/implemented
	{TLS_DHE_DSS_WITH_DES_CBC_SHA, 8, 20, 8, 8, dheDSSKA, suiteDSS, cipherDES, macSHA1, nil},
	{TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, 24, dheDSSKA, suiteDSS, cipher3DES, macSHA1, nil},
	{TLS_DHE_RSA_WITH_DES_CBC_SHA, 8, 20, 8, 8, dheRSAKA, 0, cipherDES, macSHA1, nil},
	// WARN: DSS: Certificate not supported/implemented
	{TLS_DHE_DSS_WITH_AES_256_CBC_SHA, 32, 20, 16, 32, dheDSSKA, suiteDSS, cipherAES, macSHA1, nil},
	{TLS_DHE_DSS_WITH_AES_128_CBC_SHA256, 16, 32, 16, 16, dheDSSKA, suiteDSS | suiteTLS12, cipherAES, macSHA256, nil},
	{TLS_DHE_DSS_WITH_RC4_128_SHA, 16, 20, 0, 16, dheDSSKA, suiteDSS, cipherRC4, macSHA1, nil},
	{TLS_DHE_DSS_WITH_AES_256_CBC_SHA256, 32, 32, 16, 32, dheDSSKA, suiteDSS | suiteTLS12, cipherAES, macSHA256, nil},
	{TLS_DHE_DSS_WITH_AES_128_GCM_SHA256, 16, 0, 4, 16, dheDSSKA, suiteDSS | suiteTLS12, nil, nil, aeadAESGCM},
	{TLS_DHE_DSS_WITH_AES_256_GCM_SHA384, 32, 0, 4, 32, dheDSSKA, suiteDSS | suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
}

var stdlibCipherSuites = []*cipherSuite{
	// Ciphersuite order is chosen so that ECDHE comes before plain RSA
	// and RC4 comes before AES (because of the Lucky13 attack).
	{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, 16, ecdheRSAKA, suiteECDHE | suiteTLS12, nil, nil, aeadAESGCM},
	{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, 16, ecdheECDSAKA, suiteECDHE | suiteECDSA | suiteTLS12, nil, nil, aeadAESGCM},
	{TLS_ECDHE_RSA_WITH_RC4_128_SHA, 16, 20, 0, 16, ecdheRSAKA, suiteECDHE, cipherRC4, macSHA1, nil},
	{TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, 16, 20, 0, 16, ecdheECDSAKA, suiteECDHE | suiteECDSA, cipherRC4, macSHA1, nil},
	{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, 16, ecdheRSAKA, suiteECDHE, cipherAES, macSHA1, nil},
	{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, 16, 20, 16, 16, ecdheECDSAKA, suiteECDHE | suiteECDSA, cipherAES, macSHA1, nil},
	{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, 32, ecdheRSAKA, suiteECDHE, cipherAES, macSHA1, nil},
	{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, 32, 20, 16, 32, ecdheECDSAKA, suiteECDHE | suiteECDSA, cipherAES, macSHA1, nil},
	{TLS_RSA_WITH_RC4_128_SHA, 16, 20, 0, 16, rsaKA, 0, cipherRC4, macSHA1, nil},
	{TLS_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, 16, rsaKA, 0, cipherAES, macSHA1, nil},
	{TLS_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, 32, rsaKA, 0, cipherAES, macSHA1, nil},
	{TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, 24, ecdheRSAKA, suiteECDHE, cipher3DES, macSHA1, nil},
	{TLS_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, 24, rsaKA, 0, cipher3DES, macSHA1, nil},
}

func cipherDES(key, iv []byte, isRead bool) interface{} {
	block, _ := des.NewCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

func cipherRC2(key, iv []byte, isRead bool) interface{} {
	block, _ := rc2.NewCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

func cipherRC4(key, iv []byte, isRead bool) interface{} {
	cipher, _ := rc4.NewCipher(key)
	return cipher
}

func cipher3DES(key, iv []byte, isRead bool) interface{} {
	block, _ := des.NewTripleDESCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

func cipherAES(key, iv []byte, isRead bool) interface{} {
	block, _ := aes.NewCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

// macSHA1 returns a macFunction for the given protocol version.
func macSHA1(version uint16, key []byte) macFunction {
	if version == VersionSSL30 {
		mac := ssl30MAC{
			h:   sha1.New(),
			key: make([]byte, len(key)),
		}
		copy(mac.key, key)
		return mac
	}
	return tls10MAC{hmac.New(sha1.New, key)}
}

func macMD5(version uint16, key []byte) macFunction {
	if version == VersionSSL30 {
		mac := ssl30MAC{
			h:   md5.New(),
			key: make([]byte, len(key)),
		}
		copy(mac.key, key)
		return mac
	}
	return tls10MAC{hmac.New(md5.New, key)}
}

func macSHA256(version uint16, key []byte) macFunction {
	if version == VersionSSL30 {
		mac := ssl30MAC{
			h:   sha256.New(),
			key: make([]byte, len(key)),
		}
		copy(mac.key, key)
		return mac
	}
	return tls10MAC{hmac.New(sha256.New, key)}
}

func macSHA384(version uint16, key []byte) macFunction {
	if version == VersionSSL30 {
		mac := ssl30MAC{
			h:   sha512.New384(),
			key: make([]byte, len(key)),
		}
		copy(mac.key, key)
		return mac
	}
	return tls10MAC{hmac.New(sha512.New384, key)}
}

type macFunction interface {
	Size() int
	MAC(digestBuf, seq, header, length, data []byte) []byte
}

// fixedNonceAEAD wraps an AEAD and prefixes a fixed portion of the nonce to
// each call.
type fixedNonceAEAD struct {
	// sealNonce and openNonce are buffers where the larger nonce will be
	// constructed. Since a seal and open operation may be running
	// concurrently, there is a separate buffer for each.
	sealNonce, openNonce []byte
	aead                 cipher.AEAD
}

func (f *fixedNonceAEAD) NonceSize() int { return 8 }
func (f *fixedNonceAEAD) Overhead() int  { return f.aead.Overhead() }

func (f *fixedNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	copy(f.sealNonce[len(f.sealNonce)-8:], nonce)
	return f.aead.Seal(out, f.sealNonce, plaintext, additionalData)
}

func (f *fixedNonceAEAD) Open(out, nonce, plaintext, additionalData []byte) ([]byte, error) {
	copy(f.openNonce[len(f.openNonce)-8:], nonce)
	return f.aead.Open(out, f.openNonce, plaintext, additionalData)
}

func (f *fixedNonceAEAD) explicitNonce() bool { return true }

func aeadAESGCM(key, fixedNonce []byte) tlsAead {
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	nonce1, nonce2 := make([]byte, 12), make([]byte, 12)
	copy(nonce1, fixedNonce)
	copy(nonce2, fixedNonce)

	return &fixedNonceAEAD{nonce1, nonce2, aead}
}

// xoredNonceAEAD wraps an AEAD by XORing in a fixed pattern to the nonce
// before each call.
type xorNonceAEAD struct {
	nonceMask [aeadNonceLength]byte
	aead      cipher.AEAD
}

func (f *xorNonceAEAD) NonceSize() int        { return 8 } // 64-bit sequence number
func (f *xorNonceAEAD) Overhead() int         { return f.aead.Overhead() }
func (f *xorNonceAEAD) explicitNonceLen() int { return 0 }
func (f *xorNonceAEAD) explicitNonce() bool   { return false }

func (f *xorNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result := f.aead.Seal(out, f.nonceMask[:], plaintext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	return result
}

func (f *xorNonceAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result, err := f.aead.Open(out, f.nonceMask[:], ciphertext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	return result, err
}

const (
	aeadNonceLength = 12
)

func aeadCHACHA20POLY1305(key, fixedNonce []byte) tlsAead {
	if len(fixedNonce) != aeadNonceLength {
		panic("tls: internal error: wrong nonce length")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}

	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], fixedNonce)
	return ret
}

// ssl30MAC implements the SSLv3 MAC function, as defined in
// www.mozilla.org/projects/security/pki/nss/ssl/draft302.txt section 5.2.3.1
type ssl30MAC struct {
	h   hash.Hash
	key []byte
}

func (s ssl30MAC) Size() int {
	return s.h.Size()
}

var ssl30Pad1 = [48]byte{0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36}

var ssl30Pad2 = [48]byte{0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c}

func (s ssl30MAC) MAC(digestBuf, seq, header, length, data []byte) []byte {
	padLength := 48
	if s.h.Size() == 20 {
		padLength = 40
	}

	s.h.Reset()
	s.h.Write(s.key)
	s.h.Write(ssl30Pad1[:padLength])
	s.h.Write(seq)
	s.h.Write(header[:1])
	s.h.Write(length)
	s.h.Write(data)
	digestBuf = s.h.Sum(digestBuf[:0])

	s.h.Reset()
	s.h.Write(s.key)
	s.h.Write(ssl30Pad2[:padLength])
	s.h.Write(digestBuf)
	return s.h.Sum(digestBuf[:0])
}

// tls10MAC implements the TLS 1.0 MAC function. RFC 2246, section 6.2.3.
type tls10MAC struct {
	h hash.Hash
}

func (s tls10MAC) Size() int {
	return s.h.Size()
}

func (s tls10MAC) MAC(digestBuf, seq, header, length, data []byte) []byte {
	s.h.Reset()
	s.h.Write(seq)
	s.h.Write(header)
	s.h.Write(length)
	s.h.Write(data)
	return s.h.Sum(digestBuf[:0])
}

func rsaKA(version uint16) keyAgreement {
	return &rsaKeyAgreement{
		version: version,
		auth: &signedKeyAgreement{
			sigType: signatureRSA,
			version: version,
		},
	}
}

func rsaEphemeralKA(version uint16) keyAgreement {
	return &rsaKeyAgreement{
		version:   version,
		ephemeral: true,
		auth: &signedKeyAgreement{
			sigType: signatureRSA,
			version: version,
		},
	}
}

func ecdheECDSAKA(version uint16) keyAgreement {
	return &ecdheKeyAgreement{
		auth: &signedKeyAgreement{
			sigType: signatureECDSA,
			version: version,
		},
	}
}

func ecdheRSAKA(version uint16) keyAgreement {
	return &ecdheKeyAgreement{
		auth: &signedKeyAgreement{
			sigType: signatureRSA,
			version: version,
		},
	}
}

func dheRSAKA(version uint16) keyAgreement {
	return &dheKeyAgreement{
		auth: &signedKeyAgreement{
			sigType: signatureRSA,
			version: version,
		},
	}
}

func dheDSSKA(version uint16) keyAgreement {
	return &dheKeyAgreement{
		auth: &signedKeyAgreement{
			sigType: signatureDSA,
			version: version,
		},
	}
}

func dhAnonKA(version uint16) keyAgreement {
	return &dheKeyAgreement{
		auth: &nilKeyAgreementAuthentication{},
	}
}

// mutualCipherSuite returns a cipherSuite given a list of supported
// ciphersuites and the id requested by the peer.
func mutualCipherSuite(have []uint16, want uint16) *cipherSuite {
	for _, id := range have {
		if id == want {
			for _, suite := range implementedCipherSuites {
				if suite.id == want {
					return suite
				}
			}
			return nil
		}
	}
	return nil
}

// A list of the possible cipher suite ids. Taken from
// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml
const (
	TLS_NULL_WITH_NULL_NULL                       = 0x0000
	TLS_RSA_WITH_NULL_MD5                         = 0x0001
	TLS_RSA_WITH_NULL_SHA                         = 0x0002
	TLS_RSA_EXPORT_WITH_RC4_40_MD5                = 0x0003
	TLS_RSA_WITH_RC4_128_MD5                      = 0x0004
	TLS_RSA_WITH_RC4_128_SHA                      = 0x0005
	TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5            = 0x0006
	TLS_RSA_WITH_IDEA_CBC_SHA                     = 0x0007
	TLS_RSA_EXPORT_WITH_DES40_CBC_SHA             = 0x0008
	TLS_RSA_WITH_DES_CBC_SHA                      = 0x0009
	TLS_RSA_WITH_3DES_EDE_CBC_SHA                 = 0x000A
	TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA          = 0x000B
	TLS_DH_DSS_WITH_DES_CBC_SHA                   = 0x000C
	TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA              = 0x000D
	TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA          = 0x000E
	TLS_DH_RSA_WITH_DES_CBC_SHA                   = 0x000F
	TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA              = 0x0010
	TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA         = 0x0011
	TLS_DHE_DSS_WITH_DES_CBC_SHA                  = 0x0012
	TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA             = 0x0013
	TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA         = 0x0014
	TLS_DHE_RSA_WITH_DES_CBC_SHA                  = 0x0015
	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA             = 0x0016
	TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5            = 0x0017
	TLS_DH_ANON_WITH_RC4_128_MD5                  = 0x0018
	TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA         = 0x0019
	TLS_DH_ANON_WITH_DES_CBC_SHA                  = 0x001A
	TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA             = 0x001B
	SSL_FORTEZZA_KEA_WITH_NULL_SHA                = 0x001C
	SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA        = 0x001D
	TLS_KRB5_WITH_DES_CBC_SHA                     = 0x001E
	TLS_KRB5_WITH_3DES_EDE_CBC_SHA                = 0x001F
	TLS_KRB5_WITH_RC4_128_SHA                     = 0x0020
	TLS_KRB5_WITH_IDEA_CBC_SHA                    = 0x0021
	TLS_KRB5_WITH_DES_CBC_MD5                     = 0x0022
	TLS_KRB5_WITH_3DES_EDE_CBC_MD5                = 0x0023
	TLS_KRB5_WITH_RC4_128_MD5                     = 0x0024
	TLS_KRB5_WITH_IDEA_CBC_MD5                    = 0x0025
	TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA           = 0x0026
	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA           = 0x0027
	TLS_KRB5_EXPORT_WITH_RC4_40_SHA               = 0x0028
	TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5           = 0x0029
	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5           = 0x002A
	TLS_KRB5_EXPORT_WITH_RC4_40_MD5               = 0x002B
	TLS_PSK_WITH_NULL_SHA                         = 0x002C
	TLS_DHE_PSK_WITH_NULL_SHA                     = 0x002D
	TLS_RSA_PSK_WITH_NULL_SHA                     = 0x002E
	TLS_RSA_WITH_AES_128_CBC_SHA                  = 0x002F
	TLS_DH_DSS_WITH_AES_128_CBC_SHA               = 0x0030
	TLS_DH_RSA_WITH_AES_128_CBC_SHA               = 0x0031
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA              = 0x0032
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA              = 0x0033
	TLS_DH_ANON_WITH_AES_128_CBC_SHA              = 0x0034
	TLS_RSA_WITH_AES_256_CBC_SHA                  = 0x0035
	TLS_DH_DSS_WITH_AES_256_CBC_SHA               = 0x0036
	TLS_DH_RSA_WITH_AES_256_CBC_SHA               = 0x0037
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA              = 0x0038
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA              = 0x0039
	TLS_DH_ANON_WITH_AES_256_CBC_SHA              = 0x003A
	TLS_RSA_WITH_NULL_SHA256                      = 0x003B
	TLS_RSA_WITH_AES_128_CBC_SHA256               = 0x003C
	TLS_RSA_WITH_AES_256_CBC_SHA256               = 0x003D
	TLS_DH_DSS_WITH_AES_128_CBC_SHA256            = 0x003E
	TLS_DH_RSA_WITH_AES_128_CBC_SHA256            = 0x003F
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA256           = 0x0040
	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA             = 0x0041
	TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA          = 0x0042
	TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA          = 0x0043
	TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA         = 0x0044
	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA         = 0x0045
	TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA         = 0x0046
	TLS_RSA_EXPORT1024_WITH_RC4_56_MD5            = 0x0060
	TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5        = 0x0061
	TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA           = 0x0062
	TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA       = 0x0063
	TLS_RSA_EXPORT1024_WITH_RC4_56_SHA            = 0x0064
	TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA        = 0x0065
	TLS_DHE_DSS_WITH_RC4_128_SHA                  = 0x0066
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256           = 0x0067
	TLS_DH_DSS_WITH_AES_256_CBC_SHA256            = 0x0068
	TLS_DH_RSA_WITH_AES_256_CBC_SHA256            = 0x0069
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA256           = 0x006A
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256           = 0x006B
	TLS_DH_ANON_WITH_AES_128_CBC_SHA256           = 0x006C
	TLS_DH_ANON_WITH_AES_256_CBC_SHA256           = 0x006D
	TLS_GOSTR341094_WITH_28147_CNT_IMIT           = 0x0080
	TLS_GOSTR341001_WITH_28147_CNT_IMIT           = 0x0081
	TLS_GOSTR341094_WITH_NULL_GOSTR3411           = 0x0082
	TLS_GOSTR341001_WITH_NULL_GOSTR3411           = 0x0083
	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA             = 0x0084
	TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA          = 0x0085
	TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA          = 0x0086
	TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA         = 0x0087
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA         = 0x0088
	TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA         = 0x0089
	TLS_PSK_WITH_RC4_128_SHA                      = 0x008A
	TLS_PSK_WITH_3DES_EDE_CBC_SHA                 = 0x008B
	TLS_PSK_WITH_AES_128_CBC_SHA                  = 0x008C
	TLS_PSK_WITH_AES_256_CBC_SHA                  = 0x008D
	TLS_DHE_PSK_WITH_RC4_128_SHA                  = 0x008E
	TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA             = 0x008F
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA              = 0x0090
	TLS_DHE_PSK_WITH_AES_256_CBC_SHA              = 0x0091
	TLS_RSA_PSK_WITH_RC4_128_SHA                  = 0x0092
	TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA             = 0x0093
	TLS_RSA_PSK_WITH_AES_128_CBC_SHA              = 0x0094
	TLS_RSA_PSK_WITH_AES_256_CBC_SHA              = 0x0095
	TLS_RSA_WITH_SEED_CBC_SHA                     = 0x0096
	TLS_DH_DSS_WITH_SEED_CBC_SHA                  = 0x0097
	TLS_DH_RSA_WITH_SEED_CBC_SHA                  = 0x0098
	TLS_DHE_DSS_WITH_SEED_CBC_SHA                 = 0x0099
	TLS_DHE_RSA_WITH_SEED_CBC_SHA                 = 0x009A
	TLS_DH_ANON_WITH_SEED_CBC_SHA                 = 0x009B
	TLS_RSA_WITH_AES_128_GCM_SHA256               = 0x009C
	TLS_RSA_WITH_AES_256_GCM_SHA384               = 0x009D
	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256           = 0x009E
	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384           = 0x009F
	TLS_DH_RSA_WITH_AES_128_GCM_SHA256            = 0x00A0
	TLS_DH_RSA_WITH_AES_256_GCM_SHA384            = 0x00A1
	TLS_DHE_DSS_WITH_AES_128_GCM_SHA256           = 0x00A2
	TLS_DHE_DSS_WITH_AES_256_GCM_SHA384           = 0x00A3
	TLS_DH_DSS_WITH_AES_128_GCM_SHA256            = 0x00A4
	TLS_DH_DSS_WITH_AES_256_GCM_SHA384            = 0x00A5
	TLS_DH_ANON_WITH_AES_128_GCM_SHA256           = 0x00A6
	TLS_DH_ANON_WITH_AES_256_GCM_SHA384           = 0x00A7
	TLS_PSK_WITH_AES_128_GCM_SHA256               = 0x00A8
	TLS_PSK_WITH_AES_256_GCM_SHA384               = 0x00A9
	TLS_DHE_PSK_WITH_AES_128_GCM_SHA256           = 0x00AA
	TLS_DHE_PSK_WITH_AES_256_GCM_SHA384           = 0x00AB
	TLS_RSA_PSK_WITH_AES_128_GCM_SHA256           = 0x00AC
	TLS_RSA_PSK_WITH_AES_256_GCM_SHA384           = 0x00AD
	TLS_PSK_WITH_AES_128_CBC_SHA256               = 0x00AE
	TLS_PSK_WITH_AES_256_CBC_SHA384               = 0x00AF
	TLS_PSK_WITH_NULL_SHA256                      = 0x00B0
	TLS_PSK_WITH_NULL_SHA384                      = 0x00B1
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA256           = 0x00B2
	TLS_DHE_PSK_WITH_AES_256_CBC_SHA384           = 0x00B3
	TLS_DHE_PSK_WITH_NULL_SHA256                  = 0x00B4
	TLS_DHE_PSK_WITH_NULL_SHA384                  = 0x00B5
	TLS_RSA_PSK_WITH_AES_128_CBC_SHA256           = 0x00B6
	TLS_RSA_PSK_WITH_AES_256_CBC_SHA384           = 0x00B7
	TLS_RSA_PSK_WITH_NULL_SHA256                  = 0x00B8
	TLS_RSA_PSK_WITH_NULL_SHA384                  = 0x00B9
	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256          = 0x00BA
	TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256       = 0x00BB
	TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256       = 0x00BC
	TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256      = 0x00BD
	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256      = 0x00BE
	TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256      = 0x00BF
	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256          = 0x00C0
	TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256       = 0x00C1
	TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256       = 0x00C2
	TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256      = 0x00C3
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256      = 0x00C4
	TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256      = 0x00C5
	TLS_RENEGO_PROTECTION_REQUEST                 = 0x00FF
	TLS_FALLBACK_SCSV                             = 0x5600
	TLS_ECDH_ECDSA_WITH_NULL_SHA                  = 0xC001
	TLS_ECDH_ECDSA_WITH_RC4_128_SHA               = 0xC002
	TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA          = 0xC003
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA           = 0xC004
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA           = 0xC005
	TLS_ECDHE_ECDSA_WITH_NULL_SHA                 = 0xC006
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA              = 0xC007
	TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA         = 0xC008
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA          = 0xC009
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA          = 0xC00A
	TLS_ECDH_RSA_WITH_NULL_SHA                    = 0xC00B
	TLS_ECDH_RSA_WITH_RC4_128_SHA                 = 0xC00C
	TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA            = 0xC00D
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA             = 0xC00E
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA             = 0xC00F
	TLS_ECDHE_RSA_WITH_NULL_SHA                   = 0xC010
	TLS_ECDHE_RSA_WITH_RC4_128_SHA                = 0xC011
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA           = 0xC012
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            = 0xC013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            = 0xC014
	TLS_ECDH_ANON_WITH_NULL_SHA                   = 0xC015
	TLS_ECDH_ANON_WITH_RC4_128_SHA                = 0xC016
	TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA           = 0xC017
	TLS_ECDH_ANON_WITH_AES_128_CBC_SHA            = 0xC018
	TLS_ECDH_ANON_WITH_AES_256_CBC_SHA            = 0xC019
	TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA             = 0xC01A
	TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA         = 0xC01B
	TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA         = 0xC01C
	TLS_SRP_SHA_WITH_AES_128_CBC_SHA              = 0xC01D
	TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA          = 0xC01E
	TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA          = 0xC01F
	TLS_SRP_SHA_WITH_AES_256_CBC_SHA              = 0xC020
	TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA          = 0xC021
	TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA          = 0xC022
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256       = 0xC023
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384       = 0xC024
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256        = 0xC025
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384        = 0xC026
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256         = 0xC027
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384         = 0xC028
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256          = 0xC029
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384          = 0xC02A
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       = 0xC02B
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       = 0xC02C
	TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256        = 0xC02D
	TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384        = 0xC02E
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         = 0xC02F
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         = 0xC030
	TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256          = 0xC031
	TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384          = 0xC032
	TLS_ECDHE_PSK_WITH_RC4_128_SHA                = 0xC033
	TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA           = 0xC034
	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA            = 0xC035
	TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA            = 0xC036
	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256         = 0xC037
	TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384         = 0xC038
	TLS_ECDHE_PSK_WITH_NULL_SHA                   = 0xC039
	TLS_ECDHE_PSK_WITH_NULL_SHA256                = 0xC03A
	TLS_ECDHE_PSK_WITH_NULL_SHA384                = 0xC03B
	TLS_RSA_WITH_ARIA_128_CBC_SHA256              = 0xC03C
	TLS_RSA_WITH_ARIA_256_CBC_SHA384              = 0xC03D
	TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256           = 0xC03E
	TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384           = 0xC03F
	TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256           = 0xC040
	TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384           = 0xC041
	TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256          = 0xC042
	TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384          = 0xC043
	TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256          = 0xC044
	TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384          = 0xC045
	TLS_DH_ANON_WITH_ARIA_128_CBC_SHA256          = 0xC046
	TLS_DH_ANON_WITH_ARIA_256_CBC_SHA384          = 0xC047
	TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256      = 0xC048
	TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384      = 0xC049
	TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256       = 0xC04A
	TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384       = 0xC04B
	TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256        = 0xC04C
	TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384        = 0xC04D
	TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256         = 0xC04E
	TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384         = 0xC04F
	TLS_RSA_WITH_ARIA_128_GCM_SHA256              = 0xC050
	TLS_RSA_WITH_ARIA_256_GCM_SHA384              = 0xC051
	TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256          = 0xC052
	TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384          = 0xC053
	TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256           = 0xC054
	TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384           = 0xC055
	TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256          = 0xC056
	TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384          = 0xC057
	TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256           = 0xC058
	TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384           = 0xC059
	TLS_DH_ANON_WITH_ARIA_128_GCM_SHA256          = 0xC05A
	TLS_DH_ANON_WITH_ARIA_256_GCM_SHA384          = 0xC05B
	TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256      = 0xC05C
	TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384      = 0xC05D
	TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256       = 0xC05E
	TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384       = 0xC05F
	TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256        = 0xC060
	TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384        = 0xC061
	TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256         = 0xC062
	TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384         = 0xC063
	TLS_PSK_WITH_ARIA_128_CBC_SHA256              = 0xC064
	TLS_PSK_WITH_ARIA_256_CBC_SHA384              = 0xC065
	TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256          = 0xC066
	TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384          = 0xC067
	TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256          = 0xC068
	TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384          = 0xC069
	TLS_PSK_WITH_ARIA_128_GCM_SHA256              = 0xC06A
	TLS_PSK_WITH_ARIA_256_GCM_SHA384              = 0xC06B
	TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256          = 0xC06C
	TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384          = 0xC06D
	TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256          = 0xC06E
	TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384          = 0xC06F
	TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256        = 0xC070
	TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384        = 0xC071
	TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256  = 0xC072
	TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384  = 0xC073
	TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256   = 0xC074
	TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384   = 0xC075
	TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256    = 0xC076
	TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384    = 0xC077
	TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256     = 0xC078
	TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384     = 0xC079
	TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256          = 0xC07A
	TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384          = 0xC07B
	TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256      = 0xC07C
	TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384      = 0xC07D
	TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256       = 0xC07E
	TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384       = 0xC07F
	TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256      = 0xC080
	TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384      = 0xC081
	TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256       = 0xC082
	TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384       = 0xC083
	TLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256      = 0xC084
	TLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384      = 0xC085
	TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256  = 0xC086
	TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384  = 0xC087
	TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256   = 0xC088
	TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384   = 0xC089
	TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256    = 0xC08A
	TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384    = 0xC08B
	TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256     = 0xC08C
	TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384     = 0xC08D
	TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256          = 0xC08E
	TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384          = 0xC08F
	TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256      = 0xC090
	TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384      = 0xC091
	TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256      = 0xC092
	TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384      = 0xC093
	TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256          = 0xC094
	TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384          = 0xC095
	TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256      = 0xC096
	TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384      = 0xC097
	TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256      = 0xC098
	TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384      = 0xC099
	TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256    = 0xC09A
	TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384    = 0xC09B
	TLS_RSA_WITH_AES_128_CCM                      = 0xC09C
	TLS_RSA_WITH_AES_256_CCM                      = 0xC09D
	TLS_DHE_RSA_WITH_AES_128_CCM                  = 0xC09E
	TLS_DHE_RSA_WITH_AES_256_CCM                  = 0xC09F
	TLS_RSA_WITH_AES_128_CCM_8                    = 0xC0A0
	TLS_RSA_WITH_AES_256_CCM_8                    = 0xC0A1
	TLS_DHE_RSA_WITH_AES_128_CCM_8                = 0xC0A2
	TLS_DHE_RSA_WITH_AES_256_CCM_8                = 0xC0A3
	TLS_PSK_WITH_AES_128_CCM                      = 0xC0A4
	TLS_PSK_WITH_AES_256_CCM                      = 0xC0A5
	TLS_DHE_PSK_WITH_AES_128_CCM                  = 0xC0A6
	TLS_DHE_PSK_WITH_AES_256_CCM                  = 0xC0A7
	TLS_PSK_WITH_AES_128_CCM_8                    = 0xC0A8
	TLS_PSK_WITH_AES_256_CCM_8                    = 0xC0A9
	TLS_PSK_DHE_WITH_AES_128_CCM_8                = 0xC0AA
	TLS_PSK_DHE_WITH_AES_256_CCM_8                = 0xC0AB
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM              = 0xC0AC
	TLS_ECDHE_ECDSA_WITH_AES_256_CCM              = 0xC0AD
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8            = 0xC0AE
	TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8            = 0xC0AF
	TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256         = 0xCAFE
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = 0xCCA8
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9
	TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256     = 0xCCAA
	// Old ids for Chacha20 ciphers
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD   = 0xCC13
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD = 0xCC14
	TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD     = 0xCC15
	//SSL_RSA_FIPS_WITH_DES_CBC_SHA                 = 0xFEFE
	//SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA            = 0xFEFF
	//SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA            = 0xFFE0
	//SSL_RSA_FIPS_WITH_DES_CBC_SHA                 = 0xFFE1
	SSL_RSA_WITH_RC2_CBC_MD5        = 0xFF80
	SSL_RSA_WITH_IDEA_CBC_MD5       = 0xFF81
	SSL_RSA_WITH_DES_CBC_MD5        = 0xFF82
	SSL_RSA_WITH_3DES_EDE_CBC_MD5   = 0xFF83
	SSL_EN_RC2_128_CBC_WITH_MD5     = 0xFF03
	OP_PCL_TLS10_AES_128_CBC_SHA512 = 0xFF85
)

// RSA Ciphers
var RSACiphers = []uint16{
	TLS_RSA_WITH_RC4_128_SHA,
	TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_RSA_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_AES_128_GCM_SHA256,
}

// WARN: DSS: Certificate not supported/implemented
var DHECiphers []uint16 = []uint16{
	TLS_DHE_DSS_WITH_DES_CBC_SHA,
	TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
	TLS_DHE_RSA_WITH_DES_CBC_SHA,
	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
	TLS_DHE_DSS_WITH_RC4_128_SHA,
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
	TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
	TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

var ECDHECiphers []uint16 = []uint16{
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
}

// WARN: Anonymous, Non-ephemeral DH Kex: Not supported/implemented
// WARN: DSS: Certificate not supported/implemented
// WARN: KRB5: Supported?
var ExportCiphers []uint16 = []uint16{
	TLS_RSA_EXPORT_WITH_RC4_40_MD5,
	TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
	TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
	TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
	TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
	TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
	TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
	TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5,
	TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA,
	TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA,
	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA,
	TLS_KRB5_EXPORT_WITH_RC4_40_SHA,
	TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5,
	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5,
	TLS_KRB5_EXPORT_WITH_RC4_40_MD5,
	TLS_RSA_EXPORT1024_WITH_RC4_56_MD5,
	TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5,
	TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,
	TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
	TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,
	TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA,
}

var RSAExportCiphers []uint16 = []uint16{
	TLS_RSA_EXPORT_WITH_RC4_40_MD5,
	TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
	TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
	TLS_RSA_EXPORT1024_WITH_RC4_56_MD5,
	TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5,
	TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,
	TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,
}

var RSA512ExportCiphers []uint16 = []uint16{
	TLS_RSA_EXPORT_WITH_RC4_40_MD5,
	TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
	TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
}

var DHEExportCiphers []uint16 = []uint16{
	TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
	TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
	TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5,
	TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA,
}

var ChromeCiphers []uint16 = []uint16{
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	TLS_RSA_WITH_AES_256_GCM_SHA384,
	TLS_RSA_WITH_AES_128_GCM_SHA256,
	TLS_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_RC4_128_SHA,
	TLS_RSA_WITH_RC4_128_MD5,
	TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

var ChromeNoDHECiphers []uint16 = []uint16{
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	TLS_RSA_WITH_AES_128_GCM_SHA256,
	TLS_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_RC4_128_SHA,
	TLS_RSA_WITH_RC4_128_MD5,
	TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

var FirefoxCiphers []uint16 = []uint16{
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	// WARN: DSS: Certificate not supported/implemented
	// TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

var FirefoxNoDHECiphers []uint16 = []uint16{
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	// WARN: DSS: Certificate not supported/implemented
	// TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

var SafariCiphers []uint16 = []uint16{
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	// WARN: Anonymous, Non-ephemeral DH Kex: Not supported/implemented
	// TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
	// TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
	// TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
	// TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
	// TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
	// TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
	// TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
	// TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
	// TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
	// TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA256,
	TLS_RSA_WITH_AES_128_CBC_SHA256,
	TLS_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	TLS_RSA_WITH_RC4_128_SHA,
	TLS_RSA_WITH_RC4_128_MD5,
}

var SafariNoDHECiphers []uint16 = []uint16{
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
	TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA256,
	TLS_RSA_WITH_AES_128_CBC_SHA256,
	TLS_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	// WARN: Anonymous, Non-ephemeral DH Kex: Not supported/implemented
	// TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
	// TLS_ECDH_RSA_WITH_RC4_128_SHA,
	TLS_RSA_WITH_RC4_128_SHA,
	TLS_RSA_WITH_RC4_128_MD5,
}

var PortableCiphers []uint16 = []uint16{
	// stdlibCiphers, to preserve the default behavior for common cipher-suites that may be present
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_RC4_128_SHA,
	TLS_RSA_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	// Most of the other implemented ciphers, in a somewhat reasonable order
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_RSA_WITH_AES_256_GCM_SHA384,
	TLS_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA256,
	TLS_RSA_WITH_AES_128_CBC_SHA256,
	TLS_RSA_WITH_RC4_128_MD5,
	TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	TLS_DHE_RSA_WITH_DES_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
	TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
	TLS_RSA_EXPORT_WITH_RC4_40_MD5,
	// WARN: Anonymous, Non-ephemeral DH Kex: Not supported/implemented
	// TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA,
	// TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5,
	// TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
	// TLS_ECDH_RSA_WITH_RC4_128_SHA,
	// TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
	// TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
	// TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
	// TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
	// TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
	// TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
	// TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
	// TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
	// TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
	// TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
	// WARN: DSS: Certificate not supported/implemented
	// TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
	// TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
	// TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
	// TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
	// TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
	// TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
	// TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
	// TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
	// TLS_DHE_DSS_WITH_DES_CBC_SHA,
	// TLS_DHE_DSS_WITH_RC4_128_SHA,
}

func cipherIDInCipherIDList(cipher uint16, cipherIDList []uint16) bool {
	for _, val := range cipherIDList {
		if cipher == val {
			return true
		}
	}
	return false
}

func cipherIDInCipherList(cipherID uint16, cipherList []*cipherSuite) bool {
	for _, cipher := range cipherList {
		if cipherID == cipher.id {
			return true
		}
	}
	return false
}

var SChannelSuites []uint16 = []uint16{
	TLS_RSA_WITH_AES_128_GCM_SHA256,
	TLS_RSA_WITH_RC4_128_SHA,
}
