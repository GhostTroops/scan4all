package security

import (
	"bytes"
	"crypto/rc4"
	"errors"
)

type OracleNetworkRC4Cryptor struct {
	keyEnc  *rc4.Cipher
	enc     *rc4.Cipher
	dec     *rc4.Cipher
	keySize int
}

func NewOracleNetworkRC4Cryptor(initBuffer, iv []byte, keySize int) (*OracleNetworkRC4Cryptor, error) {
	ret := &OracleNetworkRC4Cryptor{keySize: keySize}

	var err error
	if len(initBuffer) > 0 || len(iv) > 0 {
		length := keySize / 8
		if len(initBuffer) < length {
			return nil, errors.New("RC4: Invalid key length")
		}
		initKey := append(initBuffer[len(initBuffer)-length:], 0x7B)
		initKey = append(initKey, iv...)
		ret.keyEnc, err = rc4.NewCipher(initKey)
		if err != nil {
			return nil, err
		}
	}
	err = ret.Reset()
	return ret, err
	//return &OracleNetworkRC4Cryptor{enc: enc, dec: dec}, nil
}

func (sec *OracleNetworkRC4Cryptor) Reset() error {
	var err error
	key := make([]byte, 15)
	key = append(key, bytes.Repeat([]byte{0x20}, 21)...)
	index := sec.keySize / 8
	sec.keyEnc.XORKeyStream(key[:index], key[:index])
	key[index-1] ^= 0xAA
	sec.dec, err = rc4.NewCipher(key[:index])
	if err != nil {
		return err
	}
	key[index-1] ^= 0xAA
	sec.enc, err = rc4.NewCipher(key[:index])
	return err
}

func (sec *OracleNetworkRC4Cryptor) Encrypt(input []byte) ([]byte, error) {
	output := make([]byte, len(input))
	sec.enc.XORKeyStream(output, input)
	output = append(output, 0)
	return output, nil
}

func (sec *OracleNetworkRC4Cryptor) Decrypt(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}
	output := make([]byte, len(input)-1)
	sec.dec.XORKeyStream(output, input[:len(input)-1])
	return output, nil
}
