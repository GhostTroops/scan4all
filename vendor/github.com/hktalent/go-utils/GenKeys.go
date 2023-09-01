package go_utils

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

/*
package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/base64"
    "encoding/pem"
    "fmt"
)

func main() {
    // 生成一个4096位RSA密钥对
    privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
    if err != nil {
        panic(err)
    }

    // 将私钥编码成DER格式
    derPrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

    // 将DER格式的私钥转换为PEM格式
    pemPrivateKey := pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: derPrivateKey,
    })

    // 将公钥编码成DER格式
    derPublicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
    if err != nil {
        panic(err)
    }

    // 将DER格式的公钥转换为PEM格式
    pemPublicKey := pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PUBLIC KEY",
        Bytes: derPublicKey,
    })

    // 输出Base64格式的密钥对
    fmt.Println(base64.StdEncoding.EncodeToString([]byte(input + string(pemPrivateKey) + string(pemPublicKey))))
}

*/
/*
package main

import (

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

)

	func main() {
	    // 生成一个4096位RSA密钥对
	    privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	    if err != nil {
	        panic(err)
	    }

	    // 将私钥编码成DER格式
	    derPrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

	    // 将DER格式的私钥转换为PEM格式
	    pemPrivateKey := pem.EncodeToMemory(&pem.Block{
	        Type:  "RSA PRIVATE KEY",
	        Bytes: derPrivateKey,
	    })

	    // 将公钥编码成DER格式
	    derPublicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	    if err != nil {
	        panic(err)
	    }

	    // 将DER格式的公钥转换为PEM格式
	    pemPublicKey := pem.EncodeToMemory(&pem.Block{
	        Type:  "RSA PUBLIC KEY",
	        Bytes: derPublicKey,
	    })

	    // 输出Base64格式的密钥对
	    fmt.Println(base64.StdEncoding.EncodeToString([]byte(inputStr + string(pemPrivateKey) + string(pemPublicKey))))
	}
*/
func GenKeys(input string) {
	n := 64
	padded := []byte(input)
	for len(padded) < n {
		padded = append(padded, 0)
	}
	if len(padded) > n {
		padded = padded[:n]
	}

	// generate a 4096-bit RSA key pair
	key, err := rsa.GenerateKey(bytes.NewReader(padded), 4096)
	if err != nil {
		panic(err)
	}

	// encode the public key in base64 format
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	pubKeyBase64 := base64.StdEncoding.EncodeToString(pubKeyBytes)

	// encode the private key in base64 format
	privKeyBytes := x509.MarshalPKCS1PrivateKey(key)
	privKeyBase64 := base64.StdEncoding.EncodeToString(privKeyBytes)

	fmt.Printf("Input string: %s\n", input)
	fmt.Printf("Padded string: %s\n", string(padded))
	fmt.Printf("Public key (base64): %s\n", pubKeyBase64)
	fmt.Printf("Private key (base64): %s\n", privKeyBase64)
}
