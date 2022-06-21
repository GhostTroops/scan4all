package utils

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"github.com/spaolacci/murmur3"
	"math/rand"
	"time"
)

const (
	AsciiLowercase          = "abcdefghijklmnopqrstuvwxyz"
	AsciiUppercase          = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	AsciiLetters            = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	AsciiDigits             = "0123456789"
	AsciiLowercaseAndDigits = AsciiLowercase + AsciiDigits
	AsciiUppercaseAndDigits = AsciiUppercase + AsciiDigits
	AsciiLettersAndDigits   = AsciiLetters + AsciiDigits
)

// 获取随机字符串
func RandomStr(letterBytes string, n int) string {
	randSource := rand.New(rand.NewSource(time.Now().Unix()))
	const (
		letterIdxBits = 6                    // 6 bits to represent a letter index
		letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
		letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
		//letterBytes   = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	)
	randBytes := make([]byte, n)
	for i, cache, remain := n-1, randSource.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = randSource.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			randBytes[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return string(randBytes)
}

// 获取字符串md5
func MD5(str string) string {
	c := md5.New()
	c.Write([]byte(str))
	bytes := c.Sum(nil)
	return hex.EncodeToString(bytes)
}

//反向string

func ReverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// Reference: https://github.com/Becivells/iconhash

// Mmh3Hash32 计算 mmh3 hash
func Mmh3Hash32(raw []byte) int32 {
	var h32 = murmur3.New32()
	h32.Write(raw)
	return int32(h32.Sum32())
}

// base64 encode
func Base64Encode(braw []byte) []byte {
	bckd := base64.StdEncoding.EncodeToString(braw)
	var buffer bytes.Buffer
	for i := 0; i < len(bckd); i++ {
		ch := bckd[i]
		buffer.WriteByte(ch)
		if (i+1)%76 == 0 {
			buffer.WriteByte('\n')
		}
	}
	buffer.WriteByte('\n')
	return buffer.Bytes()
}
