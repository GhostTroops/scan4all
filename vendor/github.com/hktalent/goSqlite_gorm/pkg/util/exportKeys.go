package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
)

func ExportPublicKeyAsPemStr(pubkey *rsa.PublicKey) string {
	pubkey_pem := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(pubkey)}))
	return pubkey_pem
}
func ExportPrivateKeyAsPemStr(privatekey *rsa.PrivateKey) string {
	privatekey_pem := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privatekey)}))
	return privatekey_pem
}
func ExportMsgAsPemStr(msg []byte) string {
	msg_pem := string(pem.EncodeToMemory(&pem.Block{Type: "MESSAGE", Bytes: msg}))
	return msg_pem
}

func main() {
	bits := 1024
	flag.Parse()
	args := flag.Args()

	m := args[0]

	bobPrivateKey, _ := rsa.GenerateKey(rand.Reader, bits)

	bobPublicKey := &bobPrivateKey.PublicKey

	fmt.Printf("%s\n", ExportPrivateKeyAsPemStr(bobPrivateKey))

	fmt.Printf("%s\n", ExportPublicKeyAsPemStr(bobPublicKey))

	message := []byte(m)
	label := []byte("")
	hash := sha256.New()

	ciphertext, _ := rsa.EncryptOAEP(hash, rand.Reader, bobPublicKey, message, label)

	fmt.Printf("%s\n", ExportMsgAsPemStr(ciphertext))

	plainText, _ := rsa.DecryptOAEP(hash, rand.Reader, bobPrivateKey, ciphertext, label)

	fmt.Printf("RSA decrypted to [%s]", plainText)

}
