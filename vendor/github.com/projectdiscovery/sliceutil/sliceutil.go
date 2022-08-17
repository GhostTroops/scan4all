package sliceutil

import (
	"math/rand"
	"strconv"
)

// PruneEmptyStrings from the slice
func PruneEmptyStrings(v []string) []string {
	return PruneEqual(v, "")
}

// PruneEqual removes items from the slice equal to the specified value
func PruneEqual(v []string, equalTo string) (r []string) {
	for i := range v {
		if v[i] != equalTo {
			r = append(r, v[i])
		}
	}
	return
}

// Dedupe removes duplicates from a slice of strings preserving the order
func Dedupe(v []string) (r []string) {
	seen := make(map[string]struct{})
	for _, vv := range v {
		if _, ok := seen[vv]; !ok {
			seen[vv] = struct{}{}
			r = append(r, vv)
		}
	}
	return
}

// Dedupe removes duplicates from a slice of ints preserving the order
func DedupeInt(v []int) (r []int) {
	seen := make(map[int]struct{})
	for _, vv := range v {
		if _, ok := seen[vv]; !ok {
			seen[vv] = struct{}{}
			r = append(r, vv)
		}
	}
	return
}

// PickRandom item from a slice of strings
func PickRandom(v []string) string {
	return v[rand.Intn(len(v))]
}

// Contains if a slice contains an element
func Contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// ContainsItems checks if s1 contains s2
func ContainsItems(s1 []string, s2 []string) bool {
	for _, e := range s2 {
		if !Contains(s1, e) {
			return false
		}
	}
	return true
}

// ToInt converts a slice of strings to a slice of ints
func ToInt(s []string) ([]int, error) {
	var ns []int
	for _, ss := range s {
		n, err := strconv.Atoi(ss)
		if err != nil {
			return nil, err
		}
		ns = append(ns, n)
	}
	return ns, nil
}
