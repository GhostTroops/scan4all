package go_utils

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"github.com/andybalholm/brotli"
	"hash/fnv"
	"io"
	"math/rand"
	"strings"
	"time"
)

var Tplat = "ab9cdef8ghijk0lmnopqr1stuvw2xyzAB3CDEFGHI4JKLMN5OPQRS6TUVW7XYZ"

var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

func RandondStr(length int) string {
	return StringWithCharset(length, "qwertyuiop[]\\asdfghjkl;'zxcvbnm,./`1234567890-=~!@#$%^&*()_QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>")
}

func GetMd5(data []byte) string {
	// 创建一个新的 MD5 哈希器
	h := md5.New()
	h.Write(data)
	sum := h.Sum(nil)
	return fmt.Sprintf("%x", sum)
}

/*
使用 UnBrotli 解码
*/
func BrotliBase64(data []byte) string {
	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	// Check for errors when writing to the brotli writer
	if _, err := w.Write(data); err != nil {
		return ""
	}

	// Check for errors when flushing the brotli writer
	if err := w.Flush(); err != nil {
		return ""
	}

	// Close the brotli writer to free up resources
	if err := w.Close(); err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func B64_Brotli2Str(s string) string {
	if o := UnBrotli(s); nil != o {
		return string(o)
	}
	return ""
}

/*
使用 BrotliBase64 编码
*/
func UnBrotli(s string) []byte {
	if data, err := base64.StdEncoding.DecodeString(s); nil == err {
		reader := brotli.NewReader(bytes.NewReader(data))
		// 解压缩字符串
		decompressStr, err := io.ReadAll(reader)
		if err == nil {
			return decompressStr
		}
		// 打印解压缩后的字符串
		//fmt.Println(string(decompressStr))
	}
	return nil
}

func StringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func Convert2Arr(a []interface{}) []string {
	var a1 []string
	for _, x := range a {
		a1 = append(a1, fmt.Sprintf("%v", x))
	}
	return a1
}

// 获取字符串的hash
func GetStrHash(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}

/*
数字转换为 "Bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB"
*/
func ConvertSize(size int64) (result string) {
	sizes := []string{"Bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB"}
	index := 0
	for size > 1024 {
		size /= 1024
		index++
	}
	result = fmt.Sprintf("%.2f %s", float64(size), sizes[index])
	return
}

// 随机模版
func GetRadomTemplate() string {
	a := GenerateRandomNumber(0, 62, 62)
	var b = ""
	for _, x := range a {
		b += Tplat[x : x+1]
	}
	return b
}

// 生成count个[start,end)结束的不重复的随机数
//
//	可以在一次会话中随机生成62个数字，构建 62 进制字符串模版
func GenerateRandomNumber(start int, end int, count int) []int {
	// 范围检查
	if end < start || (end-start) < count {
		return nil
	}
	// 存放结果的slice
	nums := make([]int, 0)
	//随机数生成器，加入时间戳保证每次生成的随机数不一样
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for len(nums) < count {
		// 生成随机数
		num := r.Intn((end - start)) + start
		// 查重
		exist := false
		for _, v := range nums {
			if v == num {
				exist = true
				break
			}
		}
		if !exist {
			nums = append(nums, num)
		}
	}
	return nums
}

// 将十进制转换为 任意进制,需要注意的是，域名总不能有 下划线(_)，但是可以有减号(-)
// 0 -- > 0
// 1 -- > 1
// 10-- > a
// 61-- > Z
//
//	id 需要转换的数字
//	szTemplate 模版
//	szTemplate 的长度决定进制 数据, 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ 表示 62 进制度
func TransInt64ToN(id int64, szTemplate string) string {
	n := int64(len(szTemplate))
	var shortUrl []byte
	for {
		var result byte
		number := id % n
		result = szTemplate[number]
		var tmp []byte
		tmp = append(tmp, result)
		shortUrl = append(tmp, shortUrl...)
		id = id / n
		if id == 0 {
			break
		}
	}
	return string(shortUrl)
}

func Join2Str(a [][]string) string {
	var a1 []string
	for _, x := range a {
		for _, j := range x {
			a1 = append(a1, j)
		}
	}
	return strings.Join(a1, "")
}

// N 进制逆向计算
func TransN2Int64(str string, szTemplate string) int64 {
	n := int64(len(szTemplate))
	nR := int64(0)
	for i := 0; i < len(str); i++ {
		x := strings.Index(szTemplate, str[i:i+1])
		nR = nR * n
		nR += int64(x)
	}
	return nR
}

// 字符串还原数字
func Trans62ToInt64(str string) int64 {
	return TransN2Int64(str, Tplat)
}

// 数字转 62 进制
func TransInt64To62(id int64) string {
	return TransInt64ToN(id, Tplat)
}
