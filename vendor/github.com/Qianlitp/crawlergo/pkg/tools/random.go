// 随机数相关函数
package tools

import (
	"math/rand"
	"strings"
	"time"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

const letterBytesLower = "abcdefghijklmnopqrstuvwxyz0123456789"
const (
	letterIdxBitsLower = 6                         // 6 bits to represent a letter index
	letterIdxMaskLower = 1<<letterIdxBitsLower - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMaxLower  = 63 / letterIdxBitsLower   // # of letter indices fitting in 63 bits
)

var src = rand.NewSource(time.Now().UnixNano())

// RandSeq 生成长度为n的随机序列，包含大小写字母，数字
func RandSeq(n int) string {
	sb := strings.Builder{}
	sb.Grow(n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			sb.WriteByte(letterBytes[idx])
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return sb.String()
}
