package strsim

func check(s1, s2 string) (score float64, exit bool) {
	if s1 == s2 {
		return 1.0, true
	}

	if len(s1) == 0 {
		return 0.0, true
	}

	if len(s2) == 0 {
		return 0.0, true
	}

	return 0, false
}
