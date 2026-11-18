package hkdf

import (
	"crypto/hkdf"
	"hash"
)

func Extract[H hash.Hash](h func() H, secret, salt []byte) []byte {
	res, err := hkdf.Extract(h, secret, salt)
	if err != nil {
		panic(err)
	}

	return res
}

func Expand[H hash.Hash](h func() H, pseudorandomKey []byte, info string, keyLength int) []byte {
	res, err := hkdf.Expand(h, pseudorandomKey, info, keyLength)
	if err != nil {
		panic(err)
	}

	return res
}
