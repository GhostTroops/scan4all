package strsim

import "github.com/antlabs/strsim/similarity"

// CosineConf is a configuration struct for Cosine similarity.

func Cosine() OptionFunc {

	return OptionFunc(func(o *option) {
		if o.cmp == nil {
			l := similarity.Cosine{}
			o.base64 = true
			o.cmp = l.CompareUtf8
			if o.ascii {
				o.cmp = l.CompareAscii
			}
		}
	})

}
