package strsim

import (
	"strings"
)

const (
	ignoreCase = 1 << iota
	ignoreSpace
)

var replace = strings.NewReplacer("\r", "", "\n", "", "\t", "", "\f", "", " ", "")

var modiyTab = map[int]func(s *string){

	ignoreCase: func(s *string) {
		*s = strings.ToLower(*s)
	},

	ignoreSpace: func(s *string) {
		*s = replace.Replace(*s)
	},
}

func modifyString(o *option, s *string) {
	for i := 1; i <= ignoreSpace; i <<= 1 {
		if i&o.ignore > 0 {
			modiyTab[i](s)
		}
	}
}
