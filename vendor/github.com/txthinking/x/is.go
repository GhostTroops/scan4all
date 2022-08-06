package x

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// IsEmail determine whether it is email address
func IsEmail(email string) (ok bool, err error) {
	p := `^\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$`
	ok, err = regexp.MatchString(p, email)
	return
}

// IsBankCard determine whether it is bankcard number
func IsBankCard(n int64) (ok bool, err error) {
	s := strconv.FormatInt(n, 10)
	var sum int
	var i int
	for i = 1; i < len(s); i++ {
		var now int
		now, _ = strconv.Atoi(string(s[len(s)-1-i]))
		if i%2 == 0 {
			sum += now
			continue
		}
		var _i int
		_i = now * 2
		sum += _i / 10
		sum += _i % 10
	}
	var v int
	v, _ = strconv.Atoi(string(s[len(s)-1]))
	if (sum+v)%10 == 0 {
		ok = true
	}
	return
}

// IsChineseID determine whether it is Chinese ID Card Number
func IsChineseID(s string) (ok bool, err error) {
	if len(s) != 18 {
		return
	}
	var sum int
	var i int
	for i = 1; i < len(s); i++ {
		var now int
		now, err = strconv.Atoi(string(s[len(s)-1-i]))
		if err != nil {
			return
		}
		var w int
		w = int(math.Pow(2, float64(i+1-1))) % 11
		sum += now * w
	}
	v := (12 - (sum % 11)) % 11
	if v == 10 {
		if strings.ToLower(string(s[len(s)-1])) != "x" {
			return
		}
		ok = true
		return
	}
	if string(s[len(s)-1]) != strconv.Itoa(v) {
		return
	}
	ok = true
	return
}

// IsChineseWords determine whether it is Chinese words
// Notice: NOT ALL
func IsChineseWords(words string) (ok bool, err error) {
	// every rune is chinese
	for _, c := range words {
		if !unicode.Is(unicode.Scripts["Han"], c) {
			return false, nil
		}
	}
	return true, nil
}
