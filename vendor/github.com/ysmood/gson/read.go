package gson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// JSON represent a JSON value
type JSON struct {
	lock  *sync.Mutex
	value *interface{}
}

// MarshalJSON interface
func (j JSON) MarshalJSON() ([]byte, error) {
	return json.Marshal(j.Val())
}

// JSON string
func (j JSON) JSON(prefix, indent string) string {
	buf := bytes.NewBuffer(nil)
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent(prefix, indent)
	_ = enc.Encode(j.Val())
	s := buf.String()
	return s[:len(s)-1]
}

// Raw underlaying value
func (j JSON) Raw() interface{} {
	if j.value == nil {
		return nil
	}
	return *j.value
}

// String implements fmt.Stringer interface
func (j JSON) String() string {
	return fmt.Sprintf("%v", j.Val())
}

// Get by json path. It's a shortcut for Gets.
func (j JSON) Get(path string) JSON {
	j, _ = j.Gets(Path(path)...)
	return j
}

// Has an element is found on the path
func (j JSON) Has(path string) bool {
	_, has := j.Gets(Path(path)...)
	return has
}

// Query section
type Query func(interface{}) (val interface{}, has bool)

// Gets element by path sections. If a section is not string, int, or func, it will be ignored.
// If it's a func, the value will be passed to it, the result of it will the next level.
// The last return value will be false if not found.
func (j JSON) Gets(sections ...interface{}) (JSON, bool) {
	for _, sect := range sections {
		var val interface{}
		var has bool

		if fn, ok := sect.(Query); ok {
			val, has = fn(j.Val())
		} else {
			val, has = get(reflect.ValueOf(j.Val()), sect)
		}

		if !has {
			return New(nil), false
		}
		j.value = &val
	}
	return j, true
}

func get(objVal reflect.Value, sect interface{}) (val interface{}, has bool) {
	switch k := sect.(type) {
	case int:
		if objVal.Kind() != reflect.Slice || k >= objVal.Len() {
			return
		}

		has = true
		val = objVal.Index(k).Interface()

	default:
		sectVal := reflect.ValueOf(sect)

		if objVal.Kind() != reflect.Map || !sectVal.Type().AssignableTo(objVal.Type().Key()) {
			return
		}

		v := objVal.MapIndex(sectVal)
		if !v.IsValid() {
			return
		}

		has = true
		val = v.Interface()
	}

	return
}

// Str value
func (j JSON) Str() string {
	v := j.Val()
	if v, ok := v.(string); ok {
		return v
	}
	return fmt.Sprintf("%v", v)
}

var floatType = reflect.TypeOf(.0)

// Num value
func (j JSON) Num() float64 {
	v := reflect.ValueOf(j.Val())
	if v.IsValid() && v.Type().ConvertibleTo(floatType) {
		return v.Convert(floatType).Float()
	}
	return 0
}

// Bool value
func (j JSON) Bool() bool {
	if v, ok := j.Val().(bool); ok {
		return v
	}
	return false
}

// Nil or not
func (j JSON) Nil() bool {
	return j.Val() == nil
}

var intType = reflect.TypeOf(0)

// Int value
func (j JSON) Int() int {
	v := reflect.ValueOf(j.Val())
	if v.IsValid() && v.Type().ConvertibleTo(intType) {
		return int(v.Convert(intType).Int())
	}
	return 0
}

// Map of JSON
func (j JSON) Map() map[string]JSON {
	val := reflect.ValueOf(j.Val())
	if val.IsValid() && val.Kind() == reflect.Map && val.Type().Key().Kind() == reflect.String {
		obj := map[string]JSON{}
		iter := val.MapRange()
		for iter.Next() {
			obj[iter.Key().String()] = New(iter.Value().Interface())
		}
		return obj
	}

	return make(map[string]JSON)
}

// Arr of JSON
func (j JSON) Arr() []JSON {
	val := reflect.ValueOf(j.Val())
	if val.IsValid() && val.Kind() == reflect.Slice {
		obj := []JSON{}
		l := val.Len()
		for i := 0; i < l; i++ {
			obj = append(obj, New(val.Index(i).Interface()))
		}
		return obj
	}

	return make([]JSON, 0)
}

// Join elements
func (j JSON) Join(sep string) string {
	list := []string{}

	for _, el := range j.Arr() {
		list = append(list, el.Str())
	}

	return strings.Join(list, sep)
}

var regIndex = regexp.MustCompile(`^0|([1-9]\d*)$`)

// Path from string
func Path(path string) []interface{} {
	list := strings.Split(path, ".")
	sects := make([]interface{}, len(list))
	for i, s := range list {
		if regIndex.MatchString(s) {
			index, err := strconv.ParseInt(s, 10, 64)
			if err == nil {
				sects[i] = int(index)
				continue
			}
		}
		sects[i] = s
	}
	return sects
}

// Num returns the pointer of the v
func Num(v float64) *float64 {
	return &v
}

// Int returns the pointer of the v
func Int(v int) *int {
	return &v
}

// Str returns the pointer of the v
func Str(v string) *string {
	return &v
}

// Bool returns the pointer of the v
func Bool(v bool) *bool {
	return &v
}
