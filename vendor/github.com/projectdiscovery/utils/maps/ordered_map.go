package mapsutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/projectdiscovery/utils/conversion"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"github.com/tidwall/gjson"
	"golang.org/x/exp/maps"
)

var (
	_ json.Marshaler   = &OrderedMap[string, struct{}]{}
	_ json.Unmarshaler = &OrderedMap[string, struct{}]{}
)

// OrderedMap is a map that preserves the order of elements
// Note: Order is only guaranteed for current level of OrderedMap
// nested values only have order preserved if they are also OrderedMap
type OrderedMap[k comparable, v any] struct {
	keys   []k
	m      map[k]v
	dirty  bool // mark dirty if keys are modified while iterating
	inIter bool // are we iterating now ?
}

// Set sets a value in the OrderedMap (if the key already exists, it will be overwritten)
func (o *OrderedMap[k, v]) Set(key k, value v) {
	if _, ok := o.m[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.m[key] = value
	if o.inIter {
		o.dirty = true
	}
}

// Get gets a value from the OrderedMap
func (o *OrderedMap[k, v]) Get(key k) (v, bool) {
	value, ok := o.m[key]
	return value, ok
}

// Iterate iterates over the OrderedMap in insertion order
func (o *OrderedMap[k, v]) Iterate(f func(key k, value v) bool) {
	o.inIter = true
	defer func() {
		o.inIter = false
	}()
	for _, key := range o.keys {
		// silently discard any missing keys from the map
		if _, ok := o.m[key]; !ok {
			continue
		}
		if !f(key, o.m[key]) {
			break
		}
	}
	if o.dirty {
		tmp := make([]k, len(o.m))
		for _, key := range o.keys {
			if _, ok := o.m[key]; ok {
				tmp = append(tmp, key)
			}
		}
		o.keys = tmp
		o.dirty = false
	}
}

// GetKeys returns the keys of the OrderedMap
func (o *OrderedMap[k, v]) GetKeys() []k {
	return o.keys
}

// Has checks if the OrderedMap has the provided key
func (o *OrderedMap[k, v]) Has(key k) bool {
	_, ok := o.m[key]
	return ok
}

// IsEmpty checks if the OrderedMap is empty
func (o *OrderedMap[k, v]) IsEmpty() bool {
	return len(o.keys) == 0
}

// Clone returns clone of OrderedMap
func (o *OrderedMap[k, v]) Clone() OrderedMap[k, v] {
	return OrderedMap[k, v]{
		keys: sliceutil.Clone(o.keys),
		m:    maps.Clone(o.m),
	}
}

// GetByIndex gets a value from the OrderedMap by index
func (o *OrderedMap[k, v]) GetByIndex(index int) (v, bool) {
	var t v
	if index < 0 || index >= len(o.keys) {
		return t, false
	}
	key := o.keys[index]
	return o.m[key], true
}

// Delete deletes a value from the OrderedMap
func (o *OrderedMap[k, v]) Delete(key k) {
	delete(o.m, key)
	if o.inIter {
		o.dirty = true
		return // skip delete from keys if we are iterating
	}
	for i, k := range o.keys {
		if k == key {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

// Len returns the length of the OrderedMap
func (o *OrderedMap[k, v]) Len() int {
	return len(o.keys)
}

// MarshalJSON marshals the OrderedMap to JSON
func (o OrderedMap[k, v]) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, key := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		// marshal key
		keyBin, err := json.Marshal(key)
		if err != nil {
			return nil, fmt.Errorf("marshal key: %w", err)
		}
		if len(keyBin) > 0 && keyBin[len(keyBin)-1] != '"' {
			buf.WriteByte('"')
			buf.Write(keyBin)
			buf.WriteByte('"')
		} else {
			buf.Write(keyBin)
		}
		buf.WriteByte(':')
		// marshal value
		valueBin, err := json.Marshal(o.m[key])
		if err != nil {
			return nil, fmt.Errorf("marshal value: %w", err)
		}
		buf.Write(valueBin)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

type tempStruct[k comparable] struct {
	Key k
}

// UnmarshalJSON unmarshals the OrderedMap from JSON
func (o *OrderedMap[k, v]) UnmarshalJSON(data []byte) error {
	// init
	o.m = map[k]v{}

	// we are only concerned about current level of ordered map
	// nested ordered maps are not supported or need to be supported
	// via recursive use of OrderedMap
	err := json.Unmarshal(data, &o.m)
	if err != nil {
		return err
	}

	// get type of k
	var tmpKey k
	keyKind := reflect.TypeOf(tmpKey).Kind()

	o.keys = []k{}
	// gjson is memory efficient and faster than encoding/json
	// so it shouldn't have any performance impact ( might consume some cpu though )
	result := gjson.Parse(conversion.String(data))
	result.ForEach(func(key, value gjson.Result) bool {
		if keyKind == reflect.Interface {
			// heterogeneous keys use any and assign
			o.keys = append(o.keys, any(key.Value()).(k))
			return true
		}
		if keyKind == reflect.String {
			o.keys = append(o.keys, any(key.String()).(k))
			return true
		}
		// if not use tmpStruct to unmarshal
		var temp tempStruct[k]
		err = json.Unmarshal([]byte(`{"key":`+key.String()+`}`), &temp)
		if err != nil {
			return false
		}
		o.keys = append(o.keys, temp.Key)
		return true
	})
	return nil
}

// NewOrderedMap creates a new OrderedMap
func NewOrderedMap[k comparable, v any]() OrderedMap[k, v] {
	return OrderedMap[k, v]{
		keys: []k{},
		m:    map[k]v{},
	}
}
