package similarity

type Match struct {
	S     string
	Score float64
}

type MatchResult struct {
	AllResult []*Match
	Match     *Match
	BestIndex int
}

type Compare func(s1, s2 string) float64

func findBestMatch(s string, targets []string, compare Compare) *MatchResult {
	match := make([]*Match, 0, len(targets))
	bestIndex := 0
	for k, s2 := range targets {
		score := compare(s, s2)
		match = append(match, &Match{S: s2, Score: score})

		if k == 0 {
			continue
		}

		if score > match[bestIndex].Score {
			bestIndex = k
		}
	}

	return &MatchResult{AllResult: match, Match: match[bestIndex], BestIndex: bestIndex}
}
