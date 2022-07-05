package strsim

import (
	"github.com/antlabs/strsim/similarity"
)

// 比较两个字符串相似度
func Compare(s1, s2 string, opts ...Option) float64 {
	var o option

	o.fillOption(opts...)

	return compare(s1, s2, &o)
}

// 返回相似度最高的那个字符串
func FindBestMatchOne(s string, targets []string, opts ...Option) *similarity.Match {
	r := findBestMatch(s, targets, opts...)
	return r.Match
}

// 返回相似度最高的那个字符串, 以及索引位置
func FindBestMatch(s string, targets []string, opts ...Option) *similarity.MatchResult {
	return findBestMatch(s, targets, opts...)
}
