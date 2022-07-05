package strsim

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// Compare returns a fraction between 0 and 1, which indicates the degree of
// similarity between the two strings. 0 indicates completely different strings,
// 1 indicates identical strings. The comparison is case-sensitive.
func Compare(a, b string) float64 {
	a = stripSpaces(a)
	b = stripSpaces(b)

	la, lb := len(a), len(b)
	if a == b {
		return 1.0
	}
	if la < 2 || lb < 2 {
		return 0.0
	}

	firstBigrams := map[string]int{}
	for i := range a[:la-1] {
		bigram := a[i : i+2]
		firstBigrams[bigram]++
	}

	var intersectionSize float64
	for i := range b[:lb-1] {
		bigram := b[i : i+2]
		count := firstBigrams[bigram]

		if count > 0 {
			firstBigrams[bigram] = count - 1
			intersectionSize++
		}
	}

	return 2.0 * intersectionSize / float64(la+lb-2)
}

// Match contains target string with score.
type Match struct {
	Target string
	Score  float64
}

// MatchResult contains all matches, a best match with index.
type MatchResult struct {
	Matches        []*Match
	BestMatch      *Match
	BestMatchIndex int
}

// SortedByScore sorts matches ascending by their scores.
func (mr *MatchResult) SortedByScore() {
	sort.Slice(mr.Matches, func(a, b int) bool {
		return mr.Matches[a].Score > mr.Matches[b].Score
	})
	mr.BestMatchIndex = 0
}

// FindBestMatch compares s against each string in targets.
func FindBestMatch(s string, targets []string) (*MatchResult, error) {
	if len(targets) < 1 {
		return nil, fmt.Errorf("targets parameter need at least one element")
	}

	matches := make([]*Match, 0, len(targets))
	bestMatchIndex := 0

	for i, t := range targets {
		score := Compare(s, t)
		matches = append(matches, &Match{t, score})
		if score > matches[bestMatchIndex].Score {
			bestMatchIndex = i
		}
	}

	bestMatch := matches[bestMatchIndex]

	return &MatchResult{matches, bestMatch, bestMatchIndex}, nil
}

func stripSpaces(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			// if the character is a space, drop it
			return -1
		}
		// else keep it in the string
		return r
	}, str)
}
