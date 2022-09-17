package strsim

import (
	"github.com/antlabs/strsim/similarity"
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

func modifyStrToBase64Str(o *option, s *string) {
	if o.base64 {
		// 将字符串转换为base64编码
		*s = similarity.Base64Encode(*s)
	}

}
