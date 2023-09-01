package common

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

// AES CTR stream used as a replacement for SHAKE in Dilithium[1234]-AES.
type AesStream struct {
	c       cipher.Block
	counter uint64
	nonce   uint16
}

// Create a new AesStream as a replacement of SHAKE128.  (Note that
// not all occurrences of SHAKE are replaced by AES in the AES-variants).
func NewAesStream128(key *[32]byte, nonce uint16) AesStream {
	c, _ := aes.NewCipher(key[:])
	return AesStream{c: c, nonce: nonce}
}

// Create a new AesStream as a replacement of SHAKE256.  (Note that
// not all occurrences of SHAKE are replaced by AES in the AES-variants.)
//
// Yes, in an AES mode, Dilithium throws away the last 32 bytes of a seed ...
// See the remark at the end of the caption of Figure 4 in the Round 2 spec.
func NewAesStream256(key *[64]byte, nonce uint16) AesStream {
	c, _ := aes.NewCipher(key[:32])
	return AesStream{c: c, nonce: nonce}
}

// Squeeze some more blocks from the AES CTR stream into buf.
//
// Assumes length of buf is a multiple of 16.
func (s *AesStream) SqueezeInto(buf []byte) {
	var tmp [16]byte
	binary.LittleEndian.PutUint16(tmp[:], s.nonce)

	for len(buf) != 0 {
		binary.BigEndian.PutUint64(tmp[8:], s.counter)
		s.counter++
		s.c.Encrypt(buf, tmp[:])
		buf = buf[16:]
	}
}
