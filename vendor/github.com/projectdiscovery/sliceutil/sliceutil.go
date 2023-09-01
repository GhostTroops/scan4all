package sliceutil

import (
	"math/rand"
	"strconv"
	"time"
)

// As specified here https://stackoverflow.com/a/12321192/8155097
// it's better to set the seed only once.
func init() {
	rand.Seed(time.Now().UnixNano())
}

// PruneEmptyStrings from the slice
func PruneEmptyStrings(v []string) []string {
	return PruneEqual(v, "")
}

// PruneEqual removes items from the slice equal to the specified value
func PruneEqual[T comparable](inputSlice []T, equalTo T) (r []T) {
	for i := range inputSlice {
		if inputSlice[i] != equalTo {
			r = append(r, inputSlice[i])
		}
	}

	return
}

// Dedupe removes duplicates from a slice of elements preserving the order
func Dedupe[T comparable](inputSlice []T) (result []T) {
	seen := make(map[T]struct{})
	for _, inputValue := range inputSlice {
		if _, ok := seen[inputValue]; !ok {
			seen[inputValue] = struct{}{}
			result = append(result, inputValue)
		}
	}

	return
}

// PickRandom item from a slice of elements
func PickRandom[T any](v []T) T {
	return v[rand.Intn(len(v))]
}

// Contains if a slice contains an element
func Contains[T comparable](inputSlice []T, element T) bool {
	for _, inputValue := range inputSlice {
		if inputValue == element {
			return true
		}
	}

	return false
}

// ContainsItems checks if s1 contains s2
func ContainsItems[T comparable](s1 []T, s2 []T) bool {
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
