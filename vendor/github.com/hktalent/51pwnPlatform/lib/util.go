package lib

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
)

// 基于json模型拷贝
func CopyObj[T1 any, T2 any](t1 T1, t2 *T2) *T2 {
	data, err := json.Marshal(t1)
	if err == nil {
		err = json.Unmarshal(data, t2)
		if nil == err {
			return t2
		} else {
			log.Println("CopyObj 1: ", err)
		}
	} else {
		log.Println("CopyObj 2: ", err)
	}
	return nil
}

// 二进制模式深度拷贝两个对象
func DeepCopy(src, dist interface{}) (err error) {
	buf := bytes.Buffer{}
	if err = gob.NewEncoder(&buf).Encode(src); err != nil {
		return
	}
	return gob.NewDecoder(&buf).Decode(dist)
}

// 签名
func RsaSignWithSha1(data []byte, keyBytes []byte) []byte {
	//h := sha256.New()
	//h.Write(data)
	//hashed := h.Sum(nil)

	h := sha1.New()
	h.Write(data)
	hashed := h.Sum(nil)

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		panic(errors.New("private key error"))
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("ParsePKCS8PrivateKey err", err)
		panic(err)
	}

	//signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, hashed)
	if err != nil {
		fmt.Printf("Error from signing: %s\n", err)
		panic(err)
	}

	return signature
}

//	func GetKey(k string, n int) string {
//		var nX int = n / len(k)
//		if 0 < n%len(k) {
//			nX += 1
//		}
//		return strings.Repeat(k, nX)[:n]
//	}
var GKey = "862C7D05-5239-4D45-A45E-0ABE1C22704E"
var TestSign_KEY string

// 签名
func Sign(text []byte, prikey *ecdsa.PrivateKey, key string) (string, error) {
	r, s, err := ecdsa.Sign(strings.NewReader(key), prikey, text)
	if err != nil {
		log.Println("Sign Sign Error: ", err)
		return "", err
	}
	rt, err := r.MarshalText()
	if err != nil {
		log.Println("Sign MarshalText Error: ", err)
		return "", err
	}
	st, err := s.MarshalText()
	if err != nil {
		log.Println("Sign MarshalText Error: ", err)
		return "", err
	}
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	defer w.Close()
	_, err = w.Write([]byte(string(rt) + "+" + string(st)))
	if err != nil {
		log.Println("Sign Write Error: ", err)
		return "", err
	}
	w.Flush()
	return hex.EncodeToString(b.Bytes()), nil

}
func Str2Perm(k string) (*pem.Block, error) {
	pem, next := pem.Decode([]byte(k))
	log.Println("ReadPem next: ", next)
	return pem, nil
}

func Str2Perm2(k string) *ecdsa.PrivateKey {
	privkey, err := x509.ParseECPrivateKey([]byte(k))
	if err != nil {
		log.Println("privkey ParseECPrivateKey Error: ", err)
		return nil
	}
	return privkey
}

func GenRsaKey(key string) error {
	// 生成私钥文件
	length := len([]byte(key))

	var curve elliptic.Curve

	if length >= 521/8+8 {
		curve = elliptic.P521()
	} else if length >= 384/8+8 {
		curve = elliptic.P384()
	} else if length >= 256/8+8 {
		curve = elliptic.P256()
	} else if length >= 224/8+8 {
		curve = elliptic.P224()
	}

	privateKey, err := ecdsa.GenerateKey(curve, strings.NewReader(key))
	if err != nil {
		log.Println("GenerateKey Error: ", err)
		return err
	}

	bpkey, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		log.Println("MarshalECPrivateKey Error: ", err)
		return err
	}

	block := &pem.Block{
		Type:  "Private Key",
		Bytes: bpkey,
	}
	file, err := os.Create("config/private.pem")
	if err != nil {
		log.Println("priv Create Error: ", err)
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		log.Println("priv Encode Error: ", err)
		return err
	}

	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Println("MarshalPKIXPublicKey Error: ", err)
		return err
	}
	block = &pem.Block{
		Type:  "Public Key",
		Bytes: derPkix,
	}
	file, err = os.Create("config/public.pem")
	if err != nil {
		log.Println("pub Create Error: ", err)
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		log.Println("pub Encode Error: ", err)
		return err
	}
	return nil
}

// Rsa 签名算法

// base64 解码
func Base64Decode(s string) string {
	rawDecodedText, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	return string(rawDecodedText)
}

// 编码 base64
func Base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
