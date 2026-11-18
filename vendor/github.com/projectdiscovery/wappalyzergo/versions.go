package wappalyzer

import (
	"strconv"
	"strings"
)

// isMoreSpecific reports whether version a is more specific than version b.
// A version with more segments is considered more specific (e.g. "3.6.0" over "3").
// When segment counts are equal, the numerically higher version wins.
func isMoreSpecific(a, b string) bool {
	aParts := splitParts(a)
	bParts := splitParts(b)
	if len(aParts) != len(bParts) {
		return len(aParts) > len(bParts)
	}
	return versionLess(b, a)
}

// versionLess reports whether version a < version b.
func versionLess(a, b string) bool {
	aParts := splitParts(a)
	bParts := splitParts(b)

	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}
	for i := 0; i < maxLen; i++ {
		ai := 0
		bi := 0
		if i < len(aParts) {
			ai = aParts[i]
		}
		if i < len(bParts) {
			bi = bParts[i]
		}
		if ai < bi {
			return true
		}
		if ai > bi {
			return false
		}
	}
	return false
}

// splitParts splits v on '.' and parses each piece as an integer.
// Non-numeric or empty pieces become zero.
func splitParts(v string) []int {
	fields := strings.FieldsFunc(v, func(r rune) bool {
		return r == '.'
	})
	parts := make([]int, len(fields))
	for i, f := range fields {
		if n, err := strconv.Atoi(f); err == nil {
			parts[i] = n
		}
	}
	return parts
}
