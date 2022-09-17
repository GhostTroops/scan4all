package strsim

import "github.com/antlabs/strsim/similarity"

// JaroWinkler ngram 是筛子系数需要用的一个值
func JaroWinkler(matchWindow ...int) OptionFunc {
	return OptionFunc(func(o *option) {
		mw := 0
		if len(matchWindow) > 0 {
			mw = matchWindow[0]
		}
		d := &similarity.JaroWinkler{MatchWindow: mw}
		o.cmp = d.CompareUtf8
	})
}
