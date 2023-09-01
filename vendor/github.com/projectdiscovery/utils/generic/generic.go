package generic

import (
	"bytes"
	"encoding/gob"
)

// EqualsAny checks if a base value of type T is equal to
// any of the other values of type T provided as arguments.
func EqualsAny[T comparable](base T, all ...T) bool {
	for _, v := range all {
		if v == base {
			return true
		}
	}
	return false
}

// EqualsAll checks if a base value of type T is equal to all of the
// other values of type T provided as arguments.
func EqualsAll[T comparable](base T, all ...T) bool {
	if len(all) == 0 {
		return false
	}
	for _, v := range all {
		if v != base {
			return false
		}
	}
	return true
}

// SizeOf returns the approx size of a variable in bytes
func ApproxSizeOf[T any](v T) (int, error) {
	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(v); err != nil {
		return 0, err
	}
	return buf.Len(), nil
}
