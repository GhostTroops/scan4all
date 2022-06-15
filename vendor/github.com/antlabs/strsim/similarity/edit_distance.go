package similarity

type EditDistance struct {
	// test use
	mixed int
}

// ascii
func (e *EditDistance) CompareAscii(s1, s2 string) float64 {
	cacheX := make([]int, len(s2))

	diagonal := 0
	for y, yLen := 0, len(s1); y < yLen; y++ {
		for x, xLen := 0, len(cacheX); x < xLen; x++ {
			on := x + 1
			left := y + 1
			if x == 0 {
				diagonal = y
			} else if y == 0 {
				diagonal = x
			}
			if y > 0 {
				on = cacheX[x]
			}
			if x-1 >= 0 {
				left = cacheX[x-1]
			}

			same := 0
			if s1[y] != s2[x] {
				same = 1
			}

			oldDiagonal := cacheX[x]
			cacheX[x] = min(min(on+1, left+1), same+diagonal)
			diagonal = oldDiagonal
			//fmt.Printf("left:%d on:%d diagonal:%d (min:%d)#", left, on, oldDiagonal, cacheX[x])

		}
		//fmt.Println()
	}

	e.mixed = cacheX[len(cacheX)-1]
	return 1.0 - float64(cacheX[len(cacheX)-1])/float64(max(len(s1), len(s2)))
}

// utf8
func (e *EditDistance) CompareUtf8(utf8Str1, utf8Str2 string) float64 {
	r1 := []rune(utf8Str1)
	r2 := []rune(utf8Str2)
	cacheX := make([]int, len(r2))

	diagonal := 0
	for y, yLen := 0, len(r1); y < yLen; y++ {
		for x, xLen := 0, len(cacheX); x < xLen; x++ {
			on := x + 1
			left := y + 1
			if x == 0 {
				diagonal = y
			} else if y == 0 {
				diagonal = x
			}
			if y > 0 {
				on = cacheX[x]
			}
			if x-1 >= 0 {
				left = cacheX[x-1]
			}

			same := 0
			if r1[y] != r2[x] {
				same = 1
			}

			oldDiagonal := cacheX[x]
			cacheX[x] = min(min(on+1, left+1), same+diagonal)
			diagonal = oldDiagonal

		}
	}

	e.mixed = cacheX[len(cacheX)-1]
	return 1.0 - float64(cacheX[len(cacheX)-1])/float64(max(len(r1), len(r2)))
}
