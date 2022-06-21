package reflectutil

import (
	"errors"
	"fmt"
	"reflect"
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
	case reflect.Ptr:
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
