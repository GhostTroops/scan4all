package security

import (
	"crypto/cipher"
	"crypto/des"
	"errors"
)

type OracleNetworkDESCryptor struct {
	blk cipher.Block
	iv  []byte
}

func NewOracleNetworkDESCryptor(key []byte, iv []byte) (*OracleNetworkDESCryptor, error) {
	blk, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if iv == nil {
		iv = []byte{1, 35, 69, 103, -119 + 256, -85 + 256, -51 + 256, -17 + 256}
	}
	output := &OracleNetworkDESCryptor{blk: blk, iv: iv}
	return output, nil
}

func (sec *OracleNetworkDESCryptor) Reset() error {
	return nil
}
func (sec *OracleNetworkDESCryptor) Encrypt(input []byte) ([]byte, error) {
	//padding := 0
	//if len(input)%8 > 0 {
	//	padding = 8 - (len(input) % 8)
	//	input = append(input, bytes.Repeat([]byte{0}, padding)...)
	//}
	//enc := cipher.NewCBCEncrypter(sec.blk, sec.iv)
	//output := make([]byte, len(input))
	//enc.CryptBlocks(output, input)
	//return append(output, uint8(padding+1)), nil

	length := len(input)
	num := 0
	if length%8 > 0 {
		num = 8 - (length % 8)
	}
	if num > 0 {
		input = append(input, make([]byte, num)...)
	}
	output := make([]byte, length+num)

	sec.encryptBlocks(output, input)
	return append(output, uint8(num+1)), nil
}

func (sec *OracleNetworkDESCryptor) Decrypt(input []byte) ([]byte, error) {
	length := len(input)
	if (length-1)%8 != 0 {
		return nil, errors.New("invalid padding from cipher text")
	}
	num := int(input[length-1])
	if num < 0 || num > 8 {
		return nil, errors.New("invalid padding from cipher text")
	}
	output := make([]byte, length-1)

	sec.decryptBlocks(output, input[:length-1])

	return output[:length-num], nil
}

func (sec *OracleNetworkDESCryptor) encryptBlocks(dst, src []byte) {
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	blockSize := 8

	iv := sec.iv
	for len(src) > 0 {
		xorBytes(dst[:blockSize], src[:blockSize], iv)
		sec.blk.Encrypt(dst[:blockSize], dst[:blockSize])

		iv = dst[:blockSize]
		src = src[blockSize:]
		dst = dst[blockSize:]
	}
	copy(sec.iv, iv)
}

func (sec *OracleNetworkDESCryptor) decryptBlocks(dst, src []byte) {
	blockSize := 8
	if len(src)%blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	if len(src) == 0 {
		return
	}

	iv := sec.iv
	tmp := make([]byte, 8)
	for len(src) > 0 {
		copy(tmp, src[:blockSize])
		sec.blk.Encrypt(dst[:blockSize], src[:blockSize])
		xorBytes(dst[:blockSize], dst[:blockSize], iv)

		copy(iv, tmp)
		src = src[blockSize:]
		dst = dst[blockSize:]
	}
	copy(sec.iv, iv)
}

func xorBytes(des, a, b []byte) {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	if n == 0 {
		return
	}
	for i := 0; i < n; i++ {
		des[i] = a[i] ^ b[i]
	}
}
