package similarity

import (
	"math"
	"unicode/utf8"
)

type Hamming struct{}

func (h *Hamming) CompareAscii(s1, s2 string) float64 {

	count := 0
	max := len(s1)
	if max < len(s2) {
		max = len(s2)
	}

	for i, j := 0, 0; i < len(s1) && j < len(s2); {

		if s1[i] != s2[j] {
			count++
		}

		i++
		j++
	}

	return 1 - (float64(count)+math.Abs(float64(len(s1)-len(s2))))/float64(max)
}

func (h *Hamming) CompareUtf8(utf8Str1, utf8Str2 string) float64 {
	count := 0

	l1 := utf8.RuneCountInString(utf8Str1)
	max := l1

	l2 := utf8.RuneCountInString(utf8Str2)
	if max < l2 {
		max = l2
	}

	for i, j := 0, 0; i < len(utf8Str1) && j < len(utf8Str2); {
		size := 0
		r1, size := utf8.DecodeRune(StringToBytes(utf8Str1[i:]))
		i += size

		r2, size := utf8.DecodeRune(StringToBytes(utf8Str2[j:]))
		j += size

		if r1 != r2 {
			count++
		}

	}

	return 1 - (float64(count)+math.Abs(float64(l1-l2)))/float64(max)
}
