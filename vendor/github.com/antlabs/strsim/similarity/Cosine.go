package similarity

import (
	"math"
	"unicode/utf8"
)

// Cosine similarity algorithm implementation.
type Cosine struct {
}

func (c Cosine) CompareAscii(s1, s2 string) float64 {
	return c.CompareUtf8(s1, s2)
}

func (c Cosine) CompareUtf8(utf8Str1, utf8Str2 string) float64 {
	l1 := utf8.RuneCountInString(utf8Str1)
	l2 := utf8.RuneCountInString(utf8Str2)
	//l1 := len(utf8Str1)
	//l2 := len(utf8Str2)
	l3 := utf8.RuneCountInString(base64Table)
	dirts1 := make(map[string]int, l3)
	dirts2 := make(map[string]int, l3)
	// 将base64Table转化成[]string
	base64 := StrToStrs(base64Table, l3)
	// 遍历base64对dirts1和dirts2进行初始化
	for _, v := range base64 {
		dirts1[v] = 0
		dirts2[v] = 0
	}
	// 将s1和s2分别转化成[]string
	s1s := StrToStrs(utf8Str1, l1)
	s2s := StrToStrs(utf8Str2, l2)
	// 遍历s1s和s2s
	for _, v := range s1s {
		dirts1[v]++
	}
	for _, v := range s2s {
		dirts2[v]++

	}
	// 计算s1s和s2s的向量的余弦值
	var sum1, sum2, sum3 float64
	for _, v := range base64 {
		sum1 += float64(dirts1[v]) * float64(dirts1[v])
		sum2 += float64(dirts2[v]) * float64(dirts2[v])
		sum3 += float64(dirts1[v]) * float64(dirts2[v])
	}

	return sum3 / (math.Sqrt(sum1) * math.Sqrt(sum2))

}
