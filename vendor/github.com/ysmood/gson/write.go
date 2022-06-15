package gson

import (
	"encoding/json"
	"io"
	"reflect"
	"sync"
)

// New JSON from []byte, io.Reader, or raw value.
func New(v interface{}) JSON {
	return JSON{&sync.Mutex{}, &v}
}

// NewFrom json encoded string
func NewFrom(s string) JSON {
	return New([]byte(s))
}

// UnmarshalJSON interface
func (j *JSON) UnmarshalJSON(b []byte) error {
	*j = New(b)
	return nil
}

// Val of the underlaying json value.
// The first time it's called, it will try to parse the underlying data.
func (j JSON) Val() interface{} {
	if j.value == nil {
		return nil
	}

	j.lock.Lock()
	defer j.lock.Unlock()

	for {
		val, ok := (*j.value).(JSON)
		if ok {
			*j.value = *val.value
		} else {
			break
		}
	}

	var val interface{}
	switch v := (*j.value).(type) {
	case []byte:
		_ = json.Unmarshal(v, &val)
		*j.value = val
	case io.Reader:
		_ = json.NewDecoder(v).Decode(&val)
		*j.value = val
	}

	return *j.value
}

// Set by json path. It's a shortcut for Sets.
func (j *JSON) Set(path string, val interface{}) *JSON {
	return j.Sets(val, Path(path)...)
}

var _map map[string]interface{}
var interfaceType = reflect.TypeOf(_map).Elem()

// Sets element by path sections. If a section is not string or int, it will be ignored.
func (j *JSON) Sets(target interface{}, sections ...interface{}) *JSON {
	if j.value == nil {
		*j = New(nil)
	}

	last := len(sections) - 1
	val := reflect.ValueOf(j.Val())
	override := func(v reflect.Value) {
		*j.value = v.Interface()
	}

	if last == -1 {
		*j.value = target
		return j
	}

	for i, s := range sections {
		sect := reflect.ValueOf(s)
		if val.Kind() == reflect.Interface {
			val = val.Elem()
		}

		switch sect.Kind() {
		case reflect.Int:
			k := int(sect.Int())
			if val.Kind() != reflect.Slice || val.Len() <= k {
				nArr := reflect.ValueOf(make([]interface{}, k+1))
				if val.Kind() == reflect.Slice {
					reflect.Copy(nArr, val)
				}
				val = nArr
				override(val)
			}
			if i == last {
				val.Index(k).Set(reflect.ValueOf(target))
				return j
			}
			prev := val
			val = val.Index(k)
			override = func(v reflect.Value) {
				prev.Index(k).Set(v)
			}
		default:
			targetVal := reflect.ValueOf(target)
			if val.Kind() != reflect.Map {
				val = reflect.MakeMap(reflect.MapOf(sect.Type(), interfaceType))
				override(val)
			}
			if i == last {
				val.SetMapIndex(sect, targetVal)
			}
			prev := val
			val = val.MapIndex(sect)
			override = func(v reflect.Value) {
				prev.SetMapIndex(sect, v)
			}
		}
	}
	return j
}

// Del deletes the element at the path.
func (j *JSON) Del(path string) *JSON {
	j.Dels(Path(path)...)
	return j
}

// Dels deletes the element at the path sections.
// Return true if it's deleted.
func (j *JSON) Dels(sections ...interface{}) bool {
	l := len(sections)

	if l == 0 {
		j.value = nil
		return true
	}

	last := sections[l-1]

	parent, has := j.Gets(sections[:l-1]...)
	if !has {
		return false
	}

	parentVal := reflect.ValueOf(parent.Val())
	lastVal := reflect.ValueOf(last)

	switch k := last.(type) {
	case int:
		pl := parentVal.Len()
		if parentVal.Kind() != reflect.Slice || k < 0 || k >= pl {
			return false
		}

		j.Sets(reflect.AppendSlice(
			parentVal.Slice(0, k),
			parentVal.Slice(k+1, pl),
		).Interface(), sections[:l-1]...)

	default:
		if parentVal.Kind() != reflect.Map || !lastVal.Type().AssignableTo(parentVal.Type().Key()) {
			return false
		}

		parentVal.SetMapIndex(lastVal, reflect.Value{})
	}

	return true
}
