package wappalyzer

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"
)

// ParsedPattern encapsulates a regular expression with
// additional metadata for confidence and version extraction.
type ParsedPattern struct {
	regex *regexp.Regexp
	// literals is a disjunction of literal groups. A match is possible only
	// when every string in some group is present. Empty means no safe prefilter.
	literals [][]string

	Confidence int
	Version    string
	SkipRegex  bool
}

const (
	verCap1        = `(\d+(?:\.\d+)+)` // captures 1 set of digits '\d+' followed by one or more '\.\d+' patterns
	verCap1Fill    = "__verCap1__"
	verCap1Limited = `(\d{1,20}(?:\.\d{1,20}){1,20})`

	verCap2        = `((?:\d+\.)+\d+)` // captures 1 or more '\d+\.' patterns followed by 1 set of digits '\d+'
	verCap2Fill    = "__verCap2__"
	verCap2Limited = `((?:\d{1,20}\.){1,20}\d{1,20})`
)

// literalPrefilterMin is the shortest ASCII needle that is worth indexing.
// Shorter text is too common to skip a regexp, and a branch that has nothing
// this long disables the prefilter so the regexp still runs.
const literalPrefilterMin = 3

// ParsePattern extracts information from a pattern, supporting both regex and simple patterns
func ParsePattern(pattern string) (*ParsedPattern, error) {
	parts := strings.Split(pattern, "\\;")
	p := &ParsedPattern{Confidence: 100}

	if parts[0] == "" {
		p.SkipRegex = true
	}
	for i, part := range parts {
		if i == 0 {
			if p.SkipRegex {
				continue
			}
			regexPattern := part

			// save version capture groups
			regexPattern = strings.ReplaceAll(regexPattern, verCap1, verCap1Fill)
			regexPattern = strings.ReplaceAll(regexPattern, verCap2, verCap2Fill)

			regexPattern = strings.ReplaceAll(regexPattern, "\\+", "__escapedPlus__")
			regexPattern = strings.ReplaceAll(regexPattern, "\\*", "__escapedStar__")
			regexPattern = strings.ReplaceAll(regexPattern, "+", "{1,250}")
			regexPattern = strings.ReplaceAll(regexPattern, "*", "{0,250}")
			regexPattern = strings.ReplaceAll(regexPattern, "__escapedPlus__", "\\+")
			regexPattern = strings.ReplaceAll(regexPattern, "__escapedStar__", "\\*")

			// restore version capture groups
			regexPattern = strings.ReplaceAll(regexPattern, verCap1Fill, verCap1Limited)
			regexPattern = strings.ReplaceAll(regexPattern, verCap2Fill, verCap2Limited)

			var err error
			p.regex, err = regexp.Compile("(?i)" + regexPattern)
			if err != nil {
				return nil, err
			}
			p.literals = patternLiterals(p.regex.String())
		} else {
			keyValue := strings.SplitN(part, ":", 2)
			if len(keyValue) < 2 {
				continue
			}

			switch keyValue[0] {
			case "confidence":
				conf, err := strconv.Atoi(keyValue[1])
				if err != nil {
					// If conversion fails, keep default confidence
					p.Confidence = 100
				} else {
					p.Confidence = conf
				}
			case "version":
				p.Version = keyValue[1]
			}
		}
	}
	return p, nil
}

func (p *ParsedPattern) Evaluate(target string) (bool, string) {
	return p.evaluate(target, "")
}

func (p *ParsedPattern) evaluate(target, folded string) (bool, string) {
	if p.SkipRegex {
		return true, ""
	}
	if p.regex == nil {
		return false, ""
	}
	if len(p.literals) > 0 {
		if folded == "" {
			folded = strings.ToLower(target)
		}
		if !literalsPresent(folded, p.literals) {
			return false, ""
		}
	}

	submatches := p.regex.FindStringSubmatch(target)
	if len(submatches) == 0 {
		return false, ""
	}
	extractedVersion, _ := p.extractVersion(submatches)
	return true, extractedVersion
}

// patternLiterals returns the prefilter for a compiled pattern.
// Each group is a set of literals that must all occur. Any group is enough.
func patternLiterals(pattern string) [][]string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	return selectiveLiterals(cover(re.Simplify()).groups)
}

// literalsPresent reports whether folded contains every literal of some group.
func literalsPresent(folded string, groups [][]string) bool {
	for _, group := range groups {
		if groupPresent(folded, group) {
			return true
		}
	}
	return false
}

func groupPresent(folded string, group []string) bool {
	for _, lit := range group {
		if !strings.Contains(folded, lit) {
			return false
		}
	}
	return true
}

// literalCover is a necessary literal condition for a regexp node. When every
// group is a single literal, head and tail report that each match starts or
// ends with one of them, and exact that each match is one of them.
type literalCover struct {
	groups            [][]string
	head, tail, exact bool
}

// cover returns a necessary literal condition for re.
// Empty groups mean this node proves no required literal.
func cover(re *syntax.Regexp) literalCover {
	switch re.Op {
	case syntax.OpLiteral:
		if len(re.Rune) == 0 {
			return literalCover{}
		}
		text := string(re.Rune)
		groups := asciiLiteralCover(text)
		whole := len(groups) == 1 && len(groups[0]) == 1 && len(groups[0][0]) == len(text)
		return literalCover{groups: groups, head: whole, tail: whole, exact: whole}
	case syntax.OpCapture, syntax.OpPlus:
		if len(re.Sub) == 0 {
			return literalCover{}
		}
		sub := cover(re.Sub[0])
		sub.exact = sub.exact && re.Op == syntax.OpCapture
		return sub
	case syntax.OpRepeat:
		if re.Min == 0 || len(re.Sub) == 0 {
			return literalCover{}
		}
		sub := cover(re.Sub[0])
		sub.exact = false
		return sub
	case syntax.OpConcat:
		parts := flattenConcat(re, nil)
		return coverConcat(parts)
	case syntax.OpAlternate:
		out := literalCover{groups: make([][]string, 0, len(re.Sub)), head: true, tail: true, exact: true}
		for _, sub := range re.Sub {
			branch := cover(sub)
			if len(branch.groups) == 0 {
				return literalCover{}
			}
			out.groups = append(out.groups, branch.groups...)
			out.head = out.head && branch.head
			out.tail = out.tail && branch.tail
			out.exact = out.exact && branch.exact
		}
		return out
	default:
		return literalCover{}
	}
}

func flattenConcat(re *syntax.Regexp, dst []*syntax.Regexp) []*syntax.Regexp {
	if re.Op == syntax.OpConcat {
		for _, sub := range re.Sub {
			dst = flattenConcat(sub, dst)
		}
		return dst
	}
	return append(dst, re)
}

// coverConcat AND-combines required pieces. Adjacent single literals are
// glued into one needle only when the left literal ends the text matched so
// far and the right literal starts its part, so the glued text is in every
// match. Otherwise both sides are kept, since each is still required.
func coverConcat(parts []*syntax.Regexp) literalCover {
	var acc literalCover
	for i, part := range parts {
		next := cover(part)
		if len(next.groups) == 0 {
			acc.tail, acc.exact = false, false
			continue
		}
		if acc.groups == nil {
			acc = next
			acc.head = next.head && i == 0
			acc.exact = next.exact && i == 0
			continue
		}
		if acc.tail && next.head {
			if glued, ok := glueLiterals(acc.groups, next.groups); ok {
				acc = literalCover{
					groups: glued,
					head:   acc.exact,
					tail:   next.exact,
					exact:  acc.exact && next.exact,
				}
				continue
			}
		}
		acc = literalCover{groups: andLiterals(acc.groups, next.groups)}
	}
	return acc
}

func glueLiterals(left, right [][]string) ([][]string, bool) {
	leftText, leftOK := singleLiterals(left)
	rightText, rightOK := singleLiterals(right)
	if !leftOK || !rightOK || len(leftText)*len(rightText) > 32 {
		return nil, false
	}
	glued := make([][]string, 0, len(leftText)*len(rightText))
	for _, a := range leftText {
		for _, b := range rightText {
			glued = append(glued, []string{a + b})
		}
	}
	return glued, true
}

func singleLiterals(groups [][]string) ([]string, bool) {
	out := make([]string, len(groups))
	for i, group := range groups {
		if len(group) != 1 {
			return nil, false
		}
		out[i] = group[0]
	}
	return out, true
}

func andLiterals(left, right [][]string) [][]string {
	if len(left) == 0 {
		return right
	}
	if len(right) == 0 {
		return left
	}
	if len(left)*len(right) > 32 {
		if literalScore(left) >= literalScore(right) {
			return left
		}
		return right
	}
	out := make([][]string, 0, len(left)*len(right))
	for _, a := range left {
		for _, b := range right {
			clause := make([]string, 0, len(a)+len(b))
			clause = append(clause, a...)
			clause = append(clause, b...)
			out = append(out, clause)
		}
	}
	return out
}

func literalScore(groups [][]string) int {
	if len(groups) == 0 {
		return -1
	}
	score := int(^uint(0) >> 1)
	for _, group := range groups {
		longest := 0
		for _, lit := range group {
			if len(lit) > longest {
				longest = len(lit)
			}
		}
		if longest < score {
			score = longest
		}
	}
	return score
}

// selectiveLiterals drops needles shorter than the minimum. A group that
// would have nothing left invalidates the whole prefilter.
func selectiveLiterals(groups [][]string) [][]string {
	if len(groups) == 0 {
		return nil
	}
	out := make([][]string, 0, len(groups))
	seenGroup := make(map[string]struct{}, len(groups))
	for _, group := range groups {
		long := make([]string, 0, len(group))
		seen := make(map[string]struct{}, len(group))
		for _, lit := range group {
			if len(lit) < literalPrefilterMin {
				continue
			}
			if _, ok := seen[lit]; ok {
				continue
			}
			seen[lit] = struct{}{}
			long = append(long, lit)
		}
		if len(long) == 0 {
			return nil
		}
		sort.Strings(long)
		key := strings.Join(long, "\x00")
		if _, ok := seenGroup[key]; ok {
			continue
		}
		seenGroup[key] = struct{}{}
		out = append(out, long)
	}
	return out
}

// asciiLiteralCover keeps the ASCII pieces of a literal. A match must contain
// those pieces even when the literal also contains a non-ASCII character.
func asciiLiteralCover(text string) [][]string {
	var clause []string
	start := -1
	for i := 0; i < len(text); i++ {
		if text[i] > unicodeASCIIMax {
			if start >= 0 {
				clause = append(clause, strings.ToLower(text[start:i]))
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		clause = append(clause, strings.ToLower(text[start:]))
	}
	if len(clause) == 0 {
		return nil
	}
	return [][]string{clause}
}

const unicodeASCIIMax = 127

// extractVersion uses the provided pattern to extract version information from a target string.
func (p *ParsedPattern) extractVersion(submatches []string) (string, error) {
	if len(submatches) == 0 {
		return "", nil // No matches found
	}

	result := p.Version
	for i, match := range submatches[1:] { // Start from 1 to skip the entire match
		placeholder := fmt.Sprintf("\\%d", i+1)
		result = strings.ReplaceAll(result, placeholder, match)
	}

	// Evaluate any ternary expressions in the result
	result, err := evaluateVersionExpression(result, submatches[1:])
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(result), nil
}

// evaluateVersionExpression handles ternary expressions in version strings.
func evaluateVersionExpression(expression string, submatches []string) (string, error) {
	if strings.Contains(expression, "?") {
		parts := strings.Split(expression, "?")
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid ternary expression: %s", expression)
		}

		trueFalseParts := strings.Split(parts[1], ":")
		if len(trueFalseParts) != 2 {
			return "", fmt.Errorf("invalid true/false parts in ternary expression: %s", expression)
		}

		if trueFalseParts[0] != "" { // Simple existence check
			if len(submatches) == 0 {
				return trueFalseParts[1], nil
			}
			return trueFalseParts[0], nil
		}
		if trueFalseParts[1] == "" {
			if len(submatches) == 0 {
				return "", nil
			}
			return trueFalseParts[0], nil
		}
		return trueFalseParts[1], nil
	}

	return expression, nil
}
