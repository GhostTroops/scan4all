package mapsutil

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/utils/errkit"
)

var (
	ErrReadOnly = errkit.New("map is currently in read-only mode")
)

// EvictionEntry represents an entry with last access time
type EvictionEntry[K, V comparable] struct {
	Key        K
	Value      V
	LastAccess time.Time
}

// SyncLock adds sync and lock capabilities to generic map
type SyncLockMap[K, V comparable] struct {
	ReadOnly atomic.Bool
	mu       sync.RWMutex
	Map      Map[K, V]

	// Eviction-related fields
	inactivityDuration time.Duration
	evictionMap        map[K]*EvictionEntry[K, V]
	lastCleanup        time.Time
	cleanupInterval    time.Duration
}

type SyncLockMapOption[K, V comparable] func(slm *SyncLockMap[K, V])

func WithMap[K, V comparable](m Map[K, V]) SyncLockMapOption[K, V] {
	return func(slm *SyncLockMap[K, V]) {
		slm.Map = m
	}
}

// WithEviction enables inactivity-based eviction policy with the specified duration
func WithEviction[K, V comparable](inactivityDuration time.Duration, cleanupInterval time.Duration) SyncLockMapOption[K, V] {
	return func(slm *SyncLockMap[K, V]) {
		slm.inactivityDuration = inactivityDuration
		slm.evictionMap = make(map[K]*EvictionEntry[K, V])
		slm.cleanupInterval = cleanupInterval
	}
}

// NewSyncLockMap creates a new SyncLockMap.
// If an existing map is provided, it is used; otherwise, a new map is created.
func NewSyncLockMap[K, V comparable](options ...SyncLockMapOption[K, V]) *SyncLockMap[K, V] {
	slm := &SyncLockMap[K, V]{}

	for _, option := range options {
		option(slm)
	}

	if slm.Map == nil {
		slm.Map = make(Map[K, V])
	}

	return slm
}

// triggerCleanupIfNeeded triggers a one-shot cleanup if it hasn't run in the cleanup interval
func (s *SyncLockMap[K, V]) triggerCleanupIfNeeded() {
	if s.inactivityDuration <= 0 {
		return
	}

	now := time.Now()

	s.mu.Lock()
	shouldCleanup := now.Sub(s.lastCleanup) >= s.cleanupInterval
	if shouldCleanup {
		s.lastCleanup = now
	}
	s.mu.Unlock()

	if shouldCleanup {
		go s.evictInactiveEntries()
	}
}

// ForceCleanup forces an immediate cleanup (useful for testing)
func (s *SyncLockMap[K, V]) ForceCleanup() {
	if s.inactivityDuration <= 0 {
		return
	}
	s.evictInactiveEntries()
}

// CleanupInactiveItems manually triggers cleanup of inactive items
// This is a public helper function that can be called externally
func (s *SyncLockMap[K, V]) CleanupInactiveItems() {
	if s.inactivityDuration <= 0 {
		return
	}
	s.evictInactiveEntries()
}

// evictInactiveEntries removes entries that have been inactive for too long
func (s *SyncLockMap[K, V]) evictInactiveEntries() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	var keysToDelete []K

	for k, entry := range s.evictionMap {
		if now.Sub(entry.LastAccess) >= s.inactivityDuration {
			keysToDelete = append(keysToDelete, k)
		}
	}

	for _, k := range keysToDelete {
		delete(s.Map, k)
		delete(s.evictionMap, k)
	}
}

// Lock the current map to read-only mode
func (s *SyncLockMap[K, V]) Lock() {
	s.ReadOnly.Store(true)
}

// Unlock the current map
func (s *SyncLockMap[K, V]) Unlock() {
	s.ReadOnly.Store(false)
}

// Set an item with syncronous access
func (s *SyncLockMap[K, V]) Set(k K, v V) error {
	if s.ReadOnly.Load() {
		return ErrReadOnly
	}

	s.mu.Lock()
	now := time.Now()

	// If eviction is enabled, handle eviction logic
	if s.inactivityDuration > 0 {
		// Update or create eviction entry
		if entry, exists := s.evictionMap[k]; exists {
			// Update existing entry
			entry.Value = v
			entry.LastAccess = now
		} else {
			// Create new entry
			s.evictionMap[k] = &EvictionEntry[K, V]{
				Key:        k,
				Value:      v,
				LastAccess: now,
			}
		}
	}

	s.Map[k] = v
	s.mu.Unlock()

	// Trigger cleanup if needed
	s.triggerCleanupIfNeeded()

	return nil
}

// Get an item with syncronous access
func (s *SyncLockMap[K, V]) Get(k K) (V, bool) {
	s.mu.RLock()
	v, ok := s.Map[k]
	s.mu.RUnlock()

	// If eviction is enabled and key exists, update last access time
	if s.inactivityDuration > 0 && ok {
		s.mu.Lock()
		if entry, exists := s.evictionMap[k]; exists {
			entry.LastAccess = time.Now()
		}
		s.mu.Unlock()
	}

	// Trigger cleanup if needed
	s.triggerCleanupIfNeeded()

	return v, ok
}

// Delete an item with syncronous access
func (s *SyncLockMap[K, V]) Delete(k K) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If eviction is enabled, clean up eviction tracking
	if s.inactivityDuration > 0 {
		delete(s.evictionMap, k)
	}

	delete(s.Map, k)
}

// Iterate with a callback function synchronously
func (s *SyncLockMap[K, V]) Iterate(f func(k K, v V) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for k, v := range s.Map {
		if err := f(k, v); err != nil {
			return err
		}
	}
	return nil
}

// Clone creates a new SyncLockMap with the same values
func (s *SyncLockMap[K, V]) Clone() *SyncLockMap[K, V] {
	s.mu.Lock()
	defer s.mu.Unlock()

	smap := &SyncLockMap[K, V]{
		ReadOnly:           atomic.Bool{},
		mu:                 sync.RWMutex{},
		Map:                s.Map.Clone(),
		inactivityDuration: s.inactivityDuration,
		cleanupInterval:    s.cleanupInterval,
	}
	smap.ReadOnly.Store(s.ReadOnly.Load())

	// If eviction is enabled, reinitialize eviction structures
	if s.inactivityDuration > 0 {
		smap.evictionMap = make(map[K]*EvictionEntry[K, V])

		// Copy eviction entries with current time
		now := time.Now()
		for k, entry := range s.evictionMap {
			smap.evictionMap[k] = &EvictionEntry[K, V]{
				Key:        k,
				Value:      entry.Value,
				LastAccess: now,
			}
		}
	}

	return smap
}

// Has checks if the current map has the provided key
func (s *SyncLockMap[K, V]) Has(key K) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.Map.Has(key)
}

// IsEmpty checks if the current map is empty
func (s *SyncLockMap[K, V]) IsEmpty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.Map.IsEmpty()
}

// IsEmpty checks if the current map is empty
func (s *SyncLockMap[K, V]) Clear() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.Map.Clear()
}

// GetKeywithValue returns the first key having value
func (s *SyncLockMap[K, V]) GetKeyWithValue(value V) (K, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.Map.GetKeyWithValue(value)
}

// Merge the current map with the provided one
func (s *SyncLockMap[K, V]) Merge(n map[K]V) error {
	if s.ReadOnly.Load() {
		return ErrReadOnly
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Map.Merge(n)
	return nil
}

// GetAll returns Copy of the current map
func (s *SyncLockMap[K, V]) GetAll() Map[K, V] {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.Map.Clone()
}
