package sliceutil

import "sync"

// SyncSlice provides a thread-safe slice for elements of any comparable type.
type SyncSlice[K comparable] struct {
	Slice []K
	mu    *sync.RWMutex
}

// NewSyncSlice initializes a new instance of SyncSlice.
func NewSyncSlice[K comparable]() *SyncSlice[K] {
	return &SyncSlice[K]{mu: &sync.RWMutex{}}
}

// Append adds elements to the end of the slice in a thread-safe manner.
func (ss *SyncSlice[K]) Append(items ...K) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.Slice = append(ss.Slice, items...)
}

// Each iterates over all elements in the slice and applies the function f to each element.
// Iteration is done in a read-locked context to prevent data race.
func (ss *SyncSlice[K]) Each(f func(i int, k K) error) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	for i, k := range ss.Slice {
		if err := f(i, k); err != nil {
			break
		}
	}
}

// Empty clears the slice by reinitializing it in a thread-safe manner.
func (ss *SyncSlice[K]) Empty() {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.Slice = make([]K, 0)
}

// Len returns the number of elements in the slice in a thread-safe manner.
func (ss *SyncSlice[K]) Len() int {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	return len(ss.Slice)
}

// Get retrieves an element by index from the slice safely.
// Returns the element and true if index is within bounds, otherwise returns zero value and false.
func (ss *SyncSlice[K]) Get(index int) (K, bool) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	if index < 0 || index >= len(ss.Slice) {
		var zero K
		return zero, false
	}
	return ss.Slice[index], true
}

// Put updates the element at the specified index in the slice in a thread-safe manner.
// Returns true if the index is within bounds, otherwise false.
func (ss *SyncSlice[K]) Put(index int, value K) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if index < 0 || index >= len(ss.Slice) {
		return false
	}
	ss.Slice[index] = value
	return true
}
