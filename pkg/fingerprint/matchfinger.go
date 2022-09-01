package fingerprint

import (
	"log"
	"regexp"
	"strings"
)

func iskeyword(str string, keyword []string, KeywordMathOr bool) (x bool, rstr string) {
	x = true
	str = strings.ToLower(str)
	for _, k := range keyword {
		if strings.Contains(str, strings.ToLower(k)) {
			x = x && true
			rstr = k
			if KeywordMathOr {
				x = true
				break
			}
		} else {
			x = x && false
		}
	}
	return x, rstr
}

func isregular(str string, keyword []string, KeywordMathOr bool) (x bool, rstr string) {
	x = true
	for _, k := range keyword {
		re, err := regexp.Compile(k)
		if nil != err {
			log.Println(k, " is error: ", err)
			return false, ""
		}
		//re := pcre.MustCompile(k, pcre.DOTALL)
		if re.Match([]byte(str)) {
			//if re.MatcherString(str, pcre.DOTALL).Matches() {
			x = x && true
			rstr = k
			if KeywordMathOr {
				x = true
				break
			}
		} else {
			x = x && false
		}
	}
	return x, rstr
}
