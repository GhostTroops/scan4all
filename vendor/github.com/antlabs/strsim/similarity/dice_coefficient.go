package similarity

import (
	"strings"
	"unicode/utf8"
)

type DiceCoefficient struct {
	Ngram int

	//test use
	l1    int
	l2    int
	mixed int
	key   []string
	test  bool
}

type value struct {
	s1Count int
	s2Count int
}

func (d *DiceCoefficient) CompareAscii(s1, s2 string) float64 {
	return d.CompareUtf8(s1, s2)
}

func (d *DiceCoefficient) setOrGet(set map[string]value, s string, add bool) (mixed, l int) {
	var key strings.Builder
	ngram := d.Ngram
	if ngram == 0 {
		ngram = 2
	}

	for i := 0; i < len(s); {
		firstSize := 0
		for j, total := 0, 0; j < ngram && i+total < len(s); j++ {
			r, size := utf8.DecodeRuneInString(s[i+total:])
			key.WriteRune(r)
			total += size
			if j == 0 {
				firstSize = size
			}

		}
		if utf8.RuneCountInString(key.String()) != ngram {
			break
		}
		val, ok := set[key.String()]
		if add {
			if !ok {
				val = value{}
			}
			val.s1Count++
		} else {

			if !ok {
				goto next
			}

			val.s2Count++
			if val.s1Count >= val.s2Count {
				mixed++
			}
		}

		set[key.String()] = val

	next:
		if d.test {
			d.key = append(d.key, key.String())
		}

		key.Reset()
		l++
		i += firstSize
	}

	return mixed, l
}

func (d *DiceCoefficient) CompareUtf8(s1, s2 string) float64 {

	set := make(map[string]value, len(s1)/3)
	//TODO 边界比如字符长度小于ngram

	mixed, l1 := d.setOrGet(set, s1, true)

	mixed, l2 := d.setOrGet(set, s2, false)

	d.l1 = l1
	d.l2 = l2
	d.mixed = mixed
	return 2.0 * float64(mixed) / float64(l1+l2)
}
