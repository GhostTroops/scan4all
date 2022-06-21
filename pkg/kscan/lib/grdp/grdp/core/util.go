package core

import (
	"crypto/rand"
	"encoding/binary"
	"unicode/utf16"
)

func Reverse(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

func Random(n int) []byte {
	const alpha = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, n)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alpha[b%byte(len(alpha))]
	}
	return bytes
}

func convertUTF16ToLittleEndianBytes(u []uint16) []byte {
	b := make([]byte, 2*len(u))
	for index, value := range u {
		binary.LittleEndian.PutUint16(b[index*2:], value)
	}
	return b
}

// s.encode('utf-16le')
func UnicodeEncode(p string) []byte {
	return convertUTF16ToLittleEndianBytes(utf16.Encode([]rune(p)))
}

func UnicodeDecode(p []byte) string {
	b := make([]byte, 2)
	n := make([]uint16, 0, len(p)/2)
	for i, v := range p {
		if i%2 == 0 {
			b[0] = v
		} else {
			b[1] = v
			a := binary.LittleEndian.Uint16(b)
			n = append(n, a)
		}
	}
	return string(utf16.Decode(n))
}
