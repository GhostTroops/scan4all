package shiro

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"

	uuid "github.com/satori/go.uuid"
)

func padding(plainText []byte, blockSize int) []byte {
	//计算要填充的长度
	n := (blockSize - len(plainText)%blockSize)
	//对原来的明文填充n个n
	temp := bytes.Repeat([]byte{byte(n)}, n)
	plainText = append(plainText, temp...)
	return plainText
}

//AES CBC加密后的payload
func aES_CBC_Encrypt(key []byte, Content []byte) string {
	block, _ := aes.NewCipher(key)
	Content = padding(Content, block.BlockSize())
	iv := uuid.NewV4().Bytes()                     //指定初始向量vi,长度和block的块尺寸一致
	blockMode := cipher.NewCBCEncrypter(block, iv) //指定CBC分组模式，返回一个BlockMode接口对象
	cipherText := make([]byte, len(Content))
	blockMode.CryptBlocks(cipherText, Content) //加密数据
	return base64.StdEncoding.EncodeToString(append(iv[:], cipherText[:]...))
}

//AES GCM 加密后的payload shiro 1.4.2版本更换为了AES-GCM加密方式
func aES_GCM_Encrypt(key []byte, Content []byte) string {
	block, _ := aes.NewCipher(key)
	nonce := make([]byte, 16)
	io.ReadFull(rand.Reader, nonce)
	aesgcm, _ := cipher.NewGCMWithNonceSize(block, 16)
	ciphertext := aesgcm.Seal(nil, nonce, Content, nil)
	return base64.StdEncoding.EncodeToString(append(nonce, ciphertext...))
}
