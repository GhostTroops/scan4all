package stringsutil

import (
	"fmt"
	"strings"
)

// https://www.dotnetperls.com/between-before-after-go

// Between extracts the string between a and b
// returns value as is and error if a or b are not found
func Between(value string, a string, b string) (string, error) {
	after, err := After(value, a)
	if err != nil {
		return value, err
	}
	final, err := Before(after, b)
	if err != nil {
		return value, err
	}
	return final, nil
}

// Before extracts the string before a from value
// returns value as is and error if a is not found
func Before(value string, a string) (string, error) {
	pos := strings.Index(value, a)
	if pos == -1 {
		return value, fmt.Errorf("%s not found in %s", a, value)
	}
	return value[0:pos], nil
}

// After extracts the string after a from value
// returns value as is and error if a is not found
func After(value string, a string) (string, error) {
	pos := strings.Index(value, a)
	if pos == -1 {
		return value, fmt.Errorf("%s not found in %s", a, value)
	}
	adjustedPos := pos + len(a)
	if adjustedPos >= len(value) {
		return value, fmt.Errorf("After: %s is not long enough to contain %s", value, a)
	}
	return value[adjustedPos:], nil
}

// HasPrefixAny checks if the string starts with any specified prefix
func HasPrefixAny(s string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// HasSuffixAny checks if the string ends with any specified suffix
func HasSuffixAny(s string, suffixes ...string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}
	return false
}

// TrimPrefixAny trims all prefixes from string in order
func TrimPrefixAny(s string, prefixes ...string) string {
	for _, prefix := range prefixes {
		s = strings.TrimPrefix(s, prefix)
	}
	return s
}

// TrimSuffixAny trims all suffixes from string in order
func TrimSuffixAny(s string, suffixes ...string) string {
	for _, suffix := range suffixes {
		s = strings.TrimSuffix(s, suffix)
	}
	return s
}

// Join concatenates the elements of its first argument to create a single string. The separator
// string sep is placed between elements in the resulting string.
func Join(elems []interface{}, sep string) string {
	switch len(elems) {
	case 0:
		return ""
	case 1:
		return fmt.Sprint(elems[0])
	}
	n := len(sep) * (len(elems) - 1)
	for i := 0; i < len(elems); i++ {
		n += len(fmt.Sprint(elems[i]))
	}

	var b strings.Builder
	b.Grow(n)
	b.WriteString(fmt.Sprint(elems[0]))
	for _, s := range elems[1:] {
		b.WriteString(sep)
		b.WriteString(fmt.Sprint(s))
	}
	return b.String()
}

// HasPrefixI is case insensitive HasPrefix
func HasPrefixI(s, prefix string) bool {
	return strings.HasPrefix(strings.ToLower(s), strings.ToLower(prefix))
}

// HasSuffixI is case insensitive HasSuffix
func HasSuffixI(s, suffix string) bool {
	return strings.HasSuffix(strings.ToLower(s), strings.ToLower(suffix))
}

// Reverse the string
func Reverse(s string) string {
	n := 0
	rune := make([]rune, len(s))
	for _, r := range s {
		rune[n] = r
		n++
	}
	rune = rune[0:n]
	for i := 0; i < n/2; i++ {
		rune[i], rune[n-1-i] = rune[n-1-i], rune[i]
	}
	return string(rune)
}

// ContainsAny returns true is s contains any specified substring
func ContainsAny(s string, ss ...string) bool {
	for _, sss := range ss {
		if strings.Contains(s, sss) {
			return true
		}
	}
	return false
}

// EqualFoldAny returns true if s is equal to any specified substring
func EqualFoldAny(s string, ss ...string) bool {
	for _, sss := range ss {
		if strings.EqualFold(s, sss) {
			return true
		}
	}
	return false
}

// IndexAt look for a substring starting at position x
func IndexAt(s, sep string, n int) int {
	idx := strings.Index(s[n:], sep)
	if idx > -1 {
		idx += n
	}
	return idx
}

// SplitAny string by a list of separators
func SplitAny(s string, seps ...string) []string {
	sepsStr := strings.Join(seps, "")
	splitter := func(r rune) bool {
		return strings.ContainsRune(sepsStr, r)
	}
	return strings.FieldsFunc(s, splitter)
}

// SlideWithLength returns all the strings of the specified length while moving forward the extraction window
func SlideWithLength(s string, l int) chan string {
	out := make(chan string)

	go func(s string, l int) {
		defer close(out)

		if len(s) < l {
			out <- s
			return
		}

		for i := 0; i < len(s); i++ {
			if i+l <= len(s) {
				out <- s[i : i+l]
			} else {
				out <- s[i:]
				break
			}
		}
	}(s, l)

	return out
}

// ReplaceAll returns a copy of the string s with all
// instances of old incrementally replaced by new.
func ReplaceAll(s, new string, olds ...string) string {
	for _, old := range olds {
		s = strings.ReplaceAll(s, old, new)
	}
	return s
}
