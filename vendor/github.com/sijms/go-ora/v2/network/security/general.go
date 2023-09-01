package security

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rc4"
	"errors"
	"hash"
)

type OracleNetworkEncryption interface {
	Reset() error
	Encrypt(input []byte) ([]byte, error)
	Decrypt(input []byte) ([]byte, error)
}

type OracleNetworkDataIntegrity interface {
	Init() error
	Compute(input []byte) []byte
	Validate(input []byte) ([]byte, error)
}

type OracleNetworkHash struct {
	Hash      hash.Hash
	keyGen    *rc4.Cipher
	encryptor *rc4.Cipher
	decryptor *rc4.Cipher
}

type OracleNetworkHash2 struct {
	Hash      hash.Hash
	buffer    []byte
	output    []byte
	input     []byte
	keyGen    cipher.BlockMode
	encryptor cipher.BlockMode
	decryptor cipher.BlockMode
}

func NewOracleNetworkHash(hash hash.Hash, key, iv []byte) (*OracleNetworkHash, error) {
	output := &OracleNetworkHash{
		Hash: hash,
	}
	var err error
	key1 := make([]byte, 5)
	copy(key1, key[len(key)-5:])
	key1 = append(key1, 0xFF)
	key1 = append(key1, iv...)
	output.keyGen, err = rc4.NewCipher(key1)
	if err != nil {
		return nil, err
	}
	err = output.Init()
	if err != nil {
		return nil, err
	}
	return output, nil
}

func NewOracleNetworkHash2(hash hash.Hash, key, iv []byte) (*OracleNetworkHash2, error) {
	output := &OracleNetworkHash2{
		buffer: make([]byte, 32),
		output: make([]byte, hash.Size()),
		input:  make([]byte, hash.Size()),
		Hash:   hash,
	}
	aesKey := make([]byte, 16)
	copy(aesKey[:5], key[:5])
	aesKey[5] = 0xFF
	blk, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	output.keyGen = cipher.NewCBCEncrypter(blk, iv[:16])
	err = output.Init()
	if err != nil {
		return nil, err
	}
	return output, nil
}

func (onh *OracleNetworkHash2) Init() error {
	onh.keyGen.CryptBlocks(onh.buffer, onh.buffer)
	key := make([]byte, 16)
	copy(key, onh.buffer[:16])
	iv := onh.buffer[16:]
	blk, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	onh.keyGen = cipher.NewCBCEncrypter(blk, iv)
	key[5] = 90
	blk, err = aes.NewCipher(key)
	if err != nil {
		return err
	}
	onh.encryptor = cipher.NewCBCEncrypter(blk, iv)
	key[5] = 180
	blk, err = aes.NewCipher(key)
	if err != nil {
		return err
	}
	onh.decryptor = cipher.NewCBCEncrypter(blk, iv)
	return nil
}

func (onh *OracleNetworkHash) Init() error {
	key2 := make([]byte, 5)
	onh.keyGen.XORKeyStream(key2, make([]byte, 5))
	var err error
	onh.encryptor, err = rc4.NewCipher(append(key2, 90))
	if err != nil {
		return err
	}
	onh.decryptor, err = rc4.NewCipher(append(key2, 180))
	return err
}

func (onh *OracleNetworkHash) Compute(input []byte) []byte {
	dst := make([]byte, onh.Hash.Size())
	onh.encryptor.XORKeyStream(dst, make([]byte, onh.Hash.Size()))
	onh.Hash.Reset()
	onh.Hash.Write(input)
	onh.Hash.Write(dst)
	return onh.Hash.Sum(nil)
}

func (onh *OracleNetworkHash2) Compute(input []byte) []byte {
	onh.encryptor.CryptBlocks(onh.output, onh.output)
	onh.Hash.Reset()
	onh.Hash.Write(input)
	onh.Hash.Write(onh.output)
	return onh.Hash.Sum(nil)
}

func (onh *OracleNetworkHash) Validate(input []byte) ([]byte, error) {
	size := onh.Hash.Size()
	if len(input) <= size {
		return nil, errors.New("data integrity check failed: size of the input lesser than hash size")
	}
	originalSize := len(input) - size
	originalInput := input[:originalSize]
	receivedHash := input[originalSize:]
	decZeros := make([]byte, size)
	onh.decryptor.XORKeyStream(decZeros, make([]byte, size))
	onh.Hash.Reset()
	onh.Hash.Write(originalInput)
	onh.Hash.Write(decZeros)
	calcHash := onh.Hash.Sum(nil)
	if bytes.Equal(receivedHash, calcHash) {
		return originalInput, nil
	}
	return nil, errors.New("data integrity check failed")
}

func (onh *OracleNetworkHash2) Validate(input []byte) ([]byte, error) {
	size := onh.Hash.Size()
	if len(input) <= size {
		return nil, errors.New("data integrity check failed: size of the input lesser than hash size")
	}
	originalSize := len(input) - size
	originalInput := input[:originalSize]
	receivedHash := input[originalSize:]
	onh.decryptor.CryptBlocks(onh.input, onh.input)
	onh.Hash.Reset()
	onh.Hash.Write(originalInput)
	onh.Hash.Write(onh.input)
	calcHash := onh.Hash.Sum(nil)
	if bytes.Equal(receivedHash, calcHash) {
		return originalInput, nil
	}
	return nil, errors.New("data integrity check failed")
}

type OracleNetworkCBCCryptor struct {
	blk cipher.Block
	iv  []byte
}

func NewOracleNetworkCBCEncrypter(key, iv []byte) (*OracleNetworkCBCCryptor, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if iv == nil {
		iv = make([]byte, 16)
	}
	output := &OracleNetworkCBCCryptor{blk: blk, iv: iv}
	return output, nil
}

func (sec *OracleNetworkCBCCryptor) Encrypt(input []byte) ([]byte, error) {
	length := len(input)
	num := 0
	if length%16 > 0 {
		num = 16 - (length % 16)
	}
	if num > 0 {
		input = append(input, make([]byte, num)...)
	}
	output := make([]byte, length+num)
	enc := cipher.NewCBCEncrypter(sec.blk, sec.iv)
	enc.CryptBlocks(output, input)
	return append(output, uint8(num+1)), nil
}

func (sec *OracleNetworkCBCCryptor) Decrypt(input []byte) ([]byte, error) {
	length := len(input)
	//length--
	if (length-1)%16 != 0 {
		return nil, errors.New("invalid padding from cipher text")
	}
	num := int(input[length-1])
	if num < 0 || num > 16 {
		return nil, errors.New("invalid padding from cipher text")
	}
	output := make([]byte, length-1)
	dec := cipher.NewCBCDecrypter(sec.blk, sec.iv)
	dec.CryptBlocks(output, input[:length-1])
	return output[:length-num], nil
}
func (set *OracleNetworkCBCCryptor) Reset() error {
	return nil
}
func PKCS5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padtext...)
}
