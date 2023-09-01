package mapsutil

import "golang.org/x/exp/maps"

// Map wraps a generic map type
type Map[K, V comparable] map[K]V

// Has checks if the current map has the provided key
func (m Map[K, V]) Has(key K) bool {
	_, ok := m[key]
	return ok
}

// GetKeys from the map as a slice
func (m Map[K, V]) GetKeys(keys ...K) []V {
	values := make([]V, len(keys))
	for i, key := range keys {
		values[i] = m[key]
	}
	return values
}

// GetOrDefault the provided key or default to the provided value
func (m Map[K, V]) GetOrDefault(key K, defaultValue V) V {
	if v, ok := m[key]; ok {
		return v
	}
	return defaultValue
}

// Get returns the value for the provided key
func (m Map[K, V]) Get(key K) (V, bool) {
	val, ok := m[key]
	return val, ok
}

// Merge the current map with the provided one
func (m Map[K, V]) Merge(n map[K]V) {
	for k, v := range n {
		m[k] = v
	}
}

// GetKeyWithValue returns the first key having value
func (m Map[K, V]) GetKeyWithValue(value V) (K, bool) {
	var zero K
	for k, v := range m {
		if v == value {
			return k, true
		}
	}

	return zero, false
}

// IsEmpty checks if the current map is empty
func (m Map[K, V]) IsEmpty() bool {
	return len(m) == 0
}

// Clone the current map
func (m Map[K, V]) Clone() Map[K, V] {
	return maps.Clone(m)
}

// Set the provided key with the provided value
func (m Map[K, V]) Set(key K, value V) {
	m[key] = value
}

// Clear the map
func (m Map[K, V]) Clear() bool {
	maps.Clear(m)
	return m.IsEmpty()
}
