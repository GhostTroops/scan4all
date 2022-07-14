package fingerprint

import (
	"log"
	"regexp"
	"strings"
)

func iskeyword(str string, keyword []string) bool {
	var x bool
	x = true
	for _, k := range keyword {
		if strings.Contains(strings.ToLower(str), strings.ToLower(k)) {
			x = x && true
		} else {
			x = x && false
		}
	}
	return x
}

func isregular(str string, keyword []string) bool {
	var x bool
	x = true
	for _, k := range keyword {
		re, err := regexp.Compile(k)
		if nil != err {
			log.Println(k, " is error: ", err)
			return false
		}
		//re := pcre.MustCompile(k, pcre.DOTALL)
		if re.Match([]byte(str)) {
			//if re.MatcherString(str, pcre.DOTALL).Matches() {
			x = x && true
		} else {
			x = x && false
		}
	}
	return x
}
