package storage

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
)

// ParseB64RSAPublicKeyFromPEM parses a base64 encoded rsa pem to a public key structure
func ParseB64RSAPublicKeyFromPEM(pubPEM string) (*rsa.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(pubPEM)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(decoded)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}

// AESEncrypt encrypts a message using AES and puts IV at the beginning of ciphertext.
func AESEncrypt(key []byte, message []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	// It's common to put IV at the beginning of the ciphertext.
	cipherText := make([]byte, aes.BlockSize+len(message))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], message)
	encMessage := make([]byte, base64.StdEncoding.EncodedLen(len(cipherText)))
	base64.StdEncoding.Encode(encMessage, cipherText)
	return string(encMessage), nil
}

func AppendMany(sep string, slices ...[]byte) []byte {
	var final [][]byte
	for _, slice := range slices {
		if len(slice) == 0 {
			continue
		}
		final = append(final, slice)
	}
	return bytes.Join(final, []byte(sep))
}
