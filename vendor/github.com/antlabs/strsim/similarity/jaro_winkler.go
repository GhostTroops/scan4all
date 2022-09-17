package similarity

import (
	"math"
	"sort"
	"unicode/utf8"
)

type JaroWinkler struct {
	MatchWindow int
	// test use
	mw int
	m  int
	t  int
}

func (j *JaroWinkler) CompareAscii(s1, s2 string) float64 {
	return j.CompareUtf8(s1, s2)
}

func (j *JaroWinkler) CompareUtf8(s1, s2 string) float64 {
	//matching window max size
	mw := max(utf8.RuneCountInString(s1), utf8.RuneCountInString(s2))/2 - 1
	if j.MatchWindow != 0 {
		mw = j.MatchWindow
	}

	m := 0

	matchSet := make(map[rune][]int, len(s1)/3)
	l1 := 0
	for _, c := range s1 {
		matchSet[c] = append(matchSet[c], l1)
		l1++
	}

	t := 0
	l2 := 0

	indexAndRune1 := make([]*check, 0, 8)
	indexAndRune2 := make([]rune, 0, 8)

	defer func() {
		for _, v := range indexAndRune1 {
			checkPool.Put(v)
		}
	}()

	for _, c := range s2 {
		indexs, ok := matchSet[c]
		l2++
		if !ok {
			continue
		}

		for k, i := range indexs {
			if i == -1 {
				continue
			}

			//fmt.Printf("_______c %c:%d:%d\n", c, l2-1-i, mw)
			if math.Abs(float64(l2-1-i)) <= float64(mw) {
				m++

				currCheck := checkPool.Get().(*check)
				currCheck.index = i
				currCheck.c = c

				indexAndRune1 = append(indexAndRune1, currCheck)

				indexAndRune2 = append(indexAndRune2, c)

				indexs[k] = -1
				break
			}
		}
	}

	m2 := float64(m)

	if m2 == 0 {
		return 0.0
	}

	sort.Slice(indexAndRune1, func(i, j int) bool {
		return indexAndRune1[i].index < indexAndRune1[j].index
	})

	for i, v := range indexAndRune1 {
		if v.c != indexAndRune2[i] {
			t++
		}
	}

	j.mw = mw
	j.m = m
	j.t = t
	//fmt.Printf("l1:%d, l2:%d, m:%d, t:%d\n", l1, l2, m, t)
	// s1 和 s2 的相同前缀长度
	prefixLength := 0
	for i := 0; i < min(len(s1), len(s2)); i++ {
		if s1[i] != s2[i] {
			break
		}
		if prefixLength <= 4 {
			prefixLength++
		} else {
			break
		}
	}
	// 影响因子 p 取值范围[0.1，0.25]，默认值为0.1
	p := 0.1

	simj := 1.0 / 3.0 * (m2/float64(l1) + m2/float64(l2) + (m2-float64(t)/2.0)/m2)

	return simj + float64(prefixLength)*p*(1.0-simj)
}
