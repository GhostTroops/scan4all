// Package ask provides a simple way of accessing nested properties in maps and arrays.
// Works great in combination with encoding/json and other packages that "Unmarshal" arbitrary data into Go data-types.
// Inspired by the get function in the lodash javascript library.
package ask

import (
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

var tokenMatcher = regexp.MustCompile(`([^[]+)?(?:\[(\d+)])?`)
var mapType = reflect.TypeOf(map[string]interface{}{})
var sliceType = reflect.TypeOf([]interface{}{})

// Answer holds result of call to For, use one of its methods to extract a value.
type Answer struct {
	value interface{}
}

func handleIntPart(current interface{}, part int) (interface{}, bool) {
	val := reflect.ValueOf(current)
	if val.IsValid() && val.CanConvert(sliceType) {
		s := val.Convert(sliceType).Interface().([]interface{})
		if part >= 0 && part < len(s) {
			return s[part], false
		}
	}
	return current, true
}

func handleStringPart(current interface{}, part string) (interface{}, bool) {
	notFound := false
	match := tokenMatcher.FindStringSubmatch(strings.TrimSpace(part))

	if len(match) == 3 {

		if match[1] != "" {
			val := reflect.ValueOf(current)
			if val.IsValid() && val.CanConvert(mapType) {
				current = val.Convert(mapType).Interface().(map[string]interface{})[match[1]]
			} else {
				notFound = true
			}
		}

		if match[2] != "" {
			index, _ := strconv.Atoi(match[2])
			return handleIntPart(current, index)
		}

	}

	return current, notFound
}

// For is used to select a path from source to return as answer.
func For(source interface{}, path string) *Answer {

	parts := strings.Split(path, ".")
	notFound := false
	current := source

	for _, part := range parts {
		current, notFound = handleStringPart(current, part)
		if notFound {
			return &Answer{}
		}
	}

	return &Answer{value: current}
}

// ForArgs is used to select a path using individual arguments from source to return as answer.
func ForArgs(source interface{}, parts ...interface{}) *Answer {

	current := source
	notFound := false

	for _, part := range parts {

		switch vt := part.(type) {
		case uint, uint8, uint16, uint32, uint64, int, int8, int16, int32, int64:
			index := reflect.ValueOf(vt).Int()
			current, notFound = handleIntPart(current, int(index))
			if notFound {
				return &Answer{}
			}
		case string:
			current, notFound = handleStringPart(current, vt)
			if notFound {
				return &Answer{}
			}
		}

	}

	return &Answer{value: current}
}

// Path does the same thing as For but uses existing answer as source.
func (a *Answer) Path(path string) *Answer {
	return For(a.value, path)
}

// PathArgs does the same thing as ForArgs but uses existing answer as source.
func (a *Answer) PathArgs(parts ...interface{}) *Answer {
	return ForArgs(a.value, parts...)
}

// Exists returns a boolean indicating if the answer exists (not nil).
func (a *Answer) Exists() bool {
	return a.value != nil
}

// Value returns the raw value as type interface{}, can be nil if no value is available.
func (a *Answer) Value() interface{} {
	return a.value
}

// Slice attempts asserting answer as a []interface{}.
// The first return value is the result, and the second indicates if the operation was successful.
// If not successful the first return value will be set to the d parameter.
func (a *Answer) Slice(d []interface{}) ([]interface{}, bool) {
	val := reflect.ValueOf(a.value)
	if val.IsValid() && val.CanConvert(sliceType) {
		return val.Convert(sliceType).Interface().([]interface{}), true
	}
	return d, false
}

// Map attempts asserting answer as a map[string]interface{}.
// The first return value is the result, and the second indicates if the operation was successful.
// If not successful the first return value will be set to the d parameter.
func (a *Answer) Map(d map[string]interface{}) (map[string]interface{}, bool) {
	val := reflect.ValueOf(a.value)
	if val.IsValid() && val.CanConvert(mapType) {
		return val.Convert(mapType).Interface().(map[string]interface{}), true
	}
	return d, false
}

// String attempts asserting answer as a string.
// The first return value is the result, and the second indicates if the operation was successful.
// If not successful the first return value will be set to the d parameter.
func (a *Answer) String(d string) (string, bool) {
	res, ok := a.value.(string)
	if ok {
		return res, ok
	}
	return d, false
}

// Bool attempts asserting answer as a bool.
// The first return value is the result, and the second indicates if the operation was successful.
// If not successful the first return value will be set to the d parameter.
func (a *Answer) Bool(d bool) (bool, bool) {
	res, ok := a.value.(bool)
	if ok {
		return res, ok
	}
	return d, false
}

// Int attempts asserting answer as a int64. Casting from other number types will be done if necessary.
// The first return value is the result, and the second indicates if the operation was successful.
// If not successful the first return value will be set to the d parameter.
func (a *Answer) Int(d int64) (int64, bool) {
	switch vt := a.value.(type) {
	case int, int8, int16, int32, int64:
		return reflect.ValueOf(vt).Int(), true
	case uint, uint8, uint16, uint32, uint64:
		val := reflect.ValueOf(vt).Uint()
		if val <= math.MaxInt64 {
			return int64(val), true
		}
	case float32, float64:
		val := reflect.ValueOf(vt).Float()
		if val >= math.MinInt64 && val <= math.MaxInt64 {
			return int64(val), true
		}
	}
	return d, false
}

// Uint attempts asserting answer as a uint64. Casting from other number types will be done if necessary.
// The first return value is the result, and the second indicates if the operation was successful.
// If not successful the first return value will be set to the d parameter.
func (a *Answer) Uint(d uint64) (uint64, bool) {
	switch vt := a.value.(type) {
	case int, int8, int16, int32, int64:
		val := reflect.ValueOf(vt).Int()
		if val >= 0 {
			return uint64(val), true
		}
	case uint, uint8, uint16, uint32, uint64:
		return reflect.ValueOf(vt).Uint(), true
	case float32, float64:
		val := reflect.ValueOf(vt).Float()
		if val >= 0 && val <= math.MaxUint64 {
			return uint64(val), true
		}
	}
	return d, false
}

// Float attempts asserting answer as a float64. Casting from other number types will be done if necessary.
// The first return value is the result, and the second indicates if the operation was successful.
// If not successful the first return value will be set to the d parameter.
func (a *Answer) Float(d float64) (float64, bool) {
	switch vt := a.value.(type) {
	case int, int8, int16, int32, int64:
		return float64(reflect.ValueOf(vt).Int()), true
	case uint, uint8, uint16, uint32, uint64:
		return float64(reflect.ValueOf(vt).Uint()), true
	case float32:
		return float64(vt), true
	case float64:
		return vt, true
	}
	return d, false
}
