package reflectutil

import (
	"errors"
	"fmt"
	"reflect"
	"unsafe"
)

type ToMapKey func(string) string

// TitleUnderscore from https://github.com/go-ini/ini/blob/5e97220809ffaa826f787728501264e9114cb834/struct.go#L46
var TitleUnderscore ToMapKey = func(raw string) string {
	newstr := make([]rune, 0, len(raw))
	for i, chr := range raw {
		if isUpper := 'A' <= chr && chr <= 'Z'; isUpper {
			if i > 0 {
				newstr = append(newstr, '_')
			}
			chr -= 'A' - 'a'
		}
		newstr = append(newstr, chr)
	}
	return string(newstr)
}

// ToMapWithDefault settings
func ToMapWithDefault(v interface{}) (map[string]interface{}, error) {
	return ToMap(v, nil, false)
}

// ToMap converts exported fields of a struct to map[string]interface{} - non exported fields are converted to string
func ToMap(v interface{}, tomapkey ToMapKey, unexported bool) (map[string]interface{}, error) {
	if tomapkey == nil {
		tomapkey = TitleUnderscore
	}
	kv := make(map[string]interface{})
	typ := reflect.TypeOf(v)
	val := reflect.ValueOf(v)
	switch typ.Kind() {
	case reflect.Pointer:
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		return nil, errors.New("only structs are supported")
	}

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		fieldName := tomapkey(field.Name)
		fieldvalue := val.Field(i)
		var fieldValueItf interface{}
		if fieldvalue.CanInterface() {
			fieldValueItf = fieldvalue.Interface()
		} else if unexported {
			fieldValueItf = getUnexportedField(fieldvalue)
		}
		if fieldValueItf != nil {
			kv[fieldName] = fieldValueItf
		}
	}
	return kv, nil
}

// we are not particularly interested to preserve the type, so just return the value as string
func getUnexportedField(field reflect.Value) interface{} {
	return fmt.Sprint(field)
}

// GetStructField obtains a reference to a field of a pointer to a struct
func GetStructField(structInstance interface{}, fieldname string) reflect.Value {
	return reflect.ValueOf(structInstance).Elem().FieldByName(fieldname)
}

// GetUnexportedField unwraps an unexported field with pointer to struct and field name
func GetUnexportedField(structInstance interface{}, fieldname string) interface{} {
	field := GetStructField(structInstance, fieldname)
	return UnwrapUnexportedField(field)
}

// UnwrapUnexportedField unwraps an unexported field
func UnwrapUnexportedField(field reflect.Value) interface{} {
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface()
}

// SetUnexportedField sets (pointer to) struct's field with the specified value
func SetUnexportedField(structInstance interface{}, fieldname string, value interface{}) {
	field := GetStructField(structInstance, fieldname)
	setUnexportedField(field, value)
}

func setUnexportedField(field reflect.Value, value interface{}) {
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).
		Elem().
		Set(reflect.ValueOf(value))
}

// SizeOf returns the size of 'v' in bytes.
// If there is an error during calculation, Of returns -1.
//
// Implementation is taken from https://github.com/DmitriyVTitov/size/blob/v1.5.0/size.go#L14 which
// in turn is inspired from binary.Size of stdlib
func SizeOf(v interface{}) int {
	// Cache with every visited pointer so we don't count two pointers
	// to the same memory twice.
	cache := make(map[uintptr]bool)
	return sizeOf(reflect.Indirect(reflect.ValueOf(v)), cache)
}

// sizeOf returns the number of bytes the actual data represented by v occupies in memory.
// If there is an error, sizeOf returns -1.
func sizeOf(v reflect.Value, cache map[uintptr]bool) int {
	switch v.Kind() {

	case reflect.Array:
		sum := 0
		for i := 0; i < v.Len(); i++ {
			s := sizeOf(v.Index(i), cache)
			if s < 0 {
				return -1
			}
			sum += s
		}

		return sum + (v.Cap()-v.Len())*int(v.Type().Elem().Size())

	case reflect.Slice:
		// return 0 if this node has been visited already
		if cache[v.Pointer()] {
			return 0
		}
		cache[v.Pointer()] = true

		sum := 0
		for i := 0; i < v.Len(); i++ {
			s := sizeOf(v.Index(i), cache)
			if s < 0 {
				return -1
			}
			sum += s
		}

		sum += (v.Cap() - v.Len()) * int(v.Type().Elem().Size())

		return sum + int(v.Type().Size())

	case reflect.Struct:
		sum := 0
		for i, n := 0, v.NumField(); i < n; i++ {
			s := sizeOf(v.Field(i), cache)
			if s < 0 {
				return -1
			}
			sum += s
		}

		// Look for struct padding.
		padding := int(v.Type().Size())
		for i, n := 0, v.NumField(); i < n; i++ {
			padding -= int(v.Field(i).Type().Size())
		}

		return sum + padding

	case reflect.String:
		s := v.String()
		ptrData := unsafe.StringData(s)
		if ptrData == nil {
			return 0
		}
		stringPtr := uintptr(*ptrData)
		if cache[stringPtr] {
			return int(v.Type().Size())
		}
		cache[stringPtr] = true
		return len(s) + int(v.Type().Size())

	case reflect.Pointer:
		// return Ptr size if this node has been visited already (infinite recursion)
		if cache[v.Pointer()] {
			return int(v.Type().Size())
		}
		cache[v.Pointer()] = true
		if v.IsNil() {
			return int(reflect.New(v.Type()).Type().Size())
		}
		s := sizeOf(reflect.Indirect(v), cache)
		if s < 0 {
			return -1
		}
		return s + int(v.Type().Size())

	case reflect.Bool,
		reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Int, reflect.Uint,
		reflect.Chan,
		reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128,
		reflect.Func:
		return int(v.Type().Size())

	case reflect.Map:
		// return 0 if this node has been visited already (infinite recursion)
		if cache[v.Pointer()] {
			return 0
		}
		cache[v.Pointer()] = true
		sum := 0
		keys := v.MapKeys()
		for i := range keys {
			val := v.MapIndex(keys[i])
			// calculate size of key and value separately
			sv := sizeOf(val, cache)
			if sv < 0 {
				return -1
			}
			sum += sv
			sk := sizeOf(keys[i], cache)
			if sk < 0 {
				return -1
			}
			sum += sk
		}
		// Include overhead due to unused map buckets.  10.79 comes
		// from https://golang.org/src/runtime/map.go.
		return sum + int(v.Type().Size()) + int(float64(len(keys))*10.79)

	case reflect.Interface:
		return sizeOf(v.Elem(), cache) + int(v.Type().Size())

	}

	return -1
}
