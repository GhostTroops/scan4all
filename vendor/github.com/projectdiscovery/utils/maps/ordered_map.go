package mapsutil

import (
	sliceutil "github.com/projectdiscovery/utils/slice"
	"golang.org/x/exp/maps"
)

// OrderedMap is a map that preserves the order of elements
type OrderedMap[k comparable, v any] struct {
	keys []k
	m    map[k]v
}

// Set sets a value in the OrderedMap (if the key already exists, it will be overwritten)
func (o *OrderedMap[k, v]) Set(key k, value v) {
	if _, ok := o.m[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.m[key] = value
}

// Get gets a value from the OrderedMap
func (o *OrderedMap[k, v]) Get(key k) (v, bool) {
	value, ok := o.m[key]
	return value, ok
}

// Iterate iterates over the OrderedMap
func (o *OrderedMap[k, v]) Iterate(f func(key k, value v) bool) {
	for _, key := range o.keys {
		if !f(key, o.m[key]) {
			break
		}
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

// NewOrderedMap creates a new OrderedMap
func NewOrderedMap[k comparable, v any]() OrderedMap[k, v] {
	return OrderedMap[k, v]{
		keys: []k{},
		m:    map[k]v{},
	}
}
