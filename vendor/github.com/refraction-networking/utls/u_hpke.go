package tls

import (
	"github.com/refraction-networking/utls/internal/hpke"
)

type HPKERawPublicKey = []byte
type HPKE_KEM_ID = uint16  // RFC 9180
type HPKE_KDF_ID = uint16  // RFC 9180
type HPKE_AEAD_ID = uint16 // RFC 9180

type HPKESymmetricCipherSuite struct {
	KdfId  HPKE_KDF_ID
	AeadId HPKE_AEAD_ID
}

const defaultHpkeKdf = hpke.KDF_HKDF_SHA256
const defaultHpkeKem = hpke.DHKEM_X25519_HKDF_SHA256
const defaultHpkeAead = hpke.AEAD_AES_128_GCM

var dummyX25519PublicKey = []byte{
	143, 38, 37, 36, 12, 6, 229, 30, 140, 27, 167, 73, 26, 100, 203, 107, 216,
	81, 163, 222, 52, 211, 54, 210, 46, 37, 78, 216, 157, 97, 241, 244,
}

// cipherLen returns the length of a ciphertext corresponding to a message of
// length mLen.
func cipherLen(a uint16, mLen int) int {
	switch a {
	case hpke.AEAD_AES_128_GCM, hpke.AEAD_AES_256_GCM, hpke.AEAD_ChaCha20Poly1305:
		return mLen + 16
	default:
		panic("hpke: invalid AEAD identifier")
	}
}
