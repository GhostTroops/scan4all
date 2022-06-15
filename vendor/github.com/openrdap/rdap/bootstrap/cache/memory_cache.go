// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

package cache

import (
	"fmt"
	"time"
)

// A MemoryCache caches Service Registry files in memory.
type MemoryCache struct {
	Timeout time.Duration
	cache   map[string][]byte
	mtime   map[string]time.Time
}

// NewMemoryCache creates a new MemoryCache.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{
		cache: make(map[string][]byte),
		mtime: make(map[string]time.Time),
		Timeout: time.Hour * 24,
	}
}

// SetTimeout sets the duration each Service Registry file can be stored before
// its State() is Expired.
func (m *MemoryCache) SetTimeout(timeout time.Duration) {
	m.Timeout = timeout
}

// Save saves the file |filename| with |data| to the cache.
func (m *MemoryCache) Save(filename string, data []byte) error {
	m.cache[filename] = make([]byte, len(data))
	copy(m.cache[filename], data)

	m.mtime[filename] = time.Now()

	return nil
}

// Load returns the file |filename| from the cache.
//
// Since Service Registry files do not change much, the file is returned even
// if its State() is Expired.
//
// An error is returned if the file is not in the cache.
func (m *MemoryCache) Load(filename string) ([]byte, error) {
	data, ok := m.cache[filename]

	if !ok {
		return nil, fmt.Errorf("File %s not in cache", filename)
	}

	result := make([]byte, len(data))
	copy(result, data)

	return result, nil
}

// State returns the cache state of the file |filename|.
//
// The returned state is one of: Absent, Good, Expired.
func (m *MemoryCache) State(filename string) FileState {
	mtime, ok := m.mtime[filename]

	if !ok {
		return Absent
	}

	expiry := mtime.Add(m.Timeout)

	if expiry.Before(time.Now()) {
		return Expired
	}

	return Good

}
