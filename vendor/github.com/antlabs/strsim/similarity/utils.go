package similarity

import (
	"encoding/base64"
	"reflect"
	"strconv"
	"unsafe"
)

const base64Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

func max(x, y int) int {
	if x < y {
		return y
	}
	return x
}

func StringToBytes(s string) (b []byte) {
	bh := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	sh := *(*reflect.StringHeader)(unsafe.Pointer(&s))
	bh.Data = sh.Data
	bh.Len = sh.Len
	bh.Cap = sh.Len
	return b
}

// Base64Encode encodes a byte slice to a base64 string.
func Base64Encode(s string) string {
	base := base64.NewEncoding(base64Table)
	bytes := StringToBytes(s)
	return base.EncodeToString(bytes)
}

// StrToStrs 字符串转化字符数组
func StrToStrs(s string, lenth int) []string {
	base := make([]string, lenth)
	for i := 0; i < lenth; i++ {
		base[i] = string(s[i])
	}
	return base
}

// StrToStrs4 每隔四个字符转换成一个字符串
func StrToStrs4(s string, lenth int) []string {
	base := make([]string, lenth/4)
	var j = 0
	for i := 0; i < lenth; i += 4 {
		//base = append(base, s[i:i+4])
		base[j] = s[i : i+4]
		j++
	}
	return base
}

// Add 加权
func Add(uint64 []int, int int) []int {
	lens := len(uint64)
	for i := 0; i < 32; i++ {
		if i < lens {
			if uint64[i] == 1 {
				uint64[i] = int
			} else {
				uint64[i] = -int
			}
		} else {
			uint64 = append(uint64, int)
		}

	}
	return uint64
}

// Int32StrToInts   将uint64转换成string
func Int32StrToInts(ins string) []int {
	uints := make([]int, 32)

	for i := 0; i < len(ins); i++ {
		if string(ins[i]) == "1" {
			uints[i] = 1
		} else if string(ins[i]) == "0" {
			uints[i] = 0
		}
	}
	return uints

}

// IntsToStr []int 转换成string
func IntsToStr(ins []int) string {
	res := ""
	for _, v := range ins {
		res += strconv.Itoa(v)
	}

	return res
}
