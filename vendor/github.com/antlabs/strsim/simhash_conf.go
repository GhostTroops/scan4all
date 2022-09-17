package strsim

import "github.com/antlabs/strsim/similarity"

func Simhash() OptionFunc {
	return OptionFunc(func(o *option) {
		if o.cmp == nil {
			l := similarity.Simhash{}
			o.base64 = true
			o.cmp = l.CompareUtf8
			if o.ascii {
				o.cmp = l.CompareAscii
			}
		}
	})

}
