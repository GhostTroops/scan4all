package strsim

import "github.com/antlabs/strsim/similarity"

// 比较两个字符串内部函数
func compare(s1, s2 string, o *option) float64 {
	if s, e := modifyStrAndCheck(o, &s1, &s2); e {
		return s
	}

	return o.cmp(s1, s2)
}

// 前处理主要涉及，修改字符串，和边界判断
func modifyStrAndCheck(o *option, s1, s2 *string) (score float64, exit bool) {
	modifyString(o, s1)
	modifyString(o, s2)
	modifyStrToBase64Str(o, s1)
	modifyStrToBase64Str(o, s2)

	return check(*s1, *s2)
}

// 记录每个targets子串的相似度打分，并且返回相似度最高的那个字符串, 内部函数
func findBestMatch(s string, targets []string, opts ...Option) *similarity.MatchResult {

	var opt option
	opt.fillOption(opts...)

	match := make([]*similarity.Match, 0, len(targets))
	bestIndex := 0
	for k, s2 := range targets {

		score := compare(s, s2, &opt)

		//fmt.Printf("score:%f(%s)(%s)\n", score, s, s2)
		match = append(match, &similarity.Match{S: s2, Score: score})

		if k == 0 {
			continue
		}

		if score > match[bestIndex].Score {
			bestIndex = k
		}
	}

	return &similarity.MatchResult{AllResult: match, Match: match[bestIndex], BestIndex: bestIndex}
}
