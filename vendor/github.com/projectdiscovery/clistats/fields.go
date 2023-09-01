package clistats

import "sync/atomic"

// AddCounter adds an uint64 counter field to the statistics client.
//
// A counter is used to track an increasing quantity, like requests,
// errors etc.
func (s *Statistics) AddCounter(id string, value uint64) {
	newUint64 := &atomic.Uint64{}
	newUint64.Store(value)
	s.counters[id] = newUint64
}

// GetCounter returns the current value of a counter.
func (s *Statistics) GetCounter(id string) (uint64, bool) {
	counter, ok := s.counters[id]
	if !ok {
		return 0, false
	}
	return counter.Load(), true
}

// IncrementCounter increments the value of a counter by a count.
func (s *Statistics) IncrementCounter(id string, count int) {
	counter, ok := s.counters[id]
	if !ok {
		return
	}
	counter.Add(uint64(count))
}

// AddStatic adds a static information field to the statistics.
//
// The value for these metrics will remain constant throughout the
// lifecycle of the statistics client. All the values will be
// converted into string and displayed as such.
func (s *Statistics) AddStatic(id string, value interface{}) {
	s.static[id] = value
}

// GetStatic returns the original value for a static field.
func (s *Statistics) GetStatic(id string) (interface{}, bool) {
	static, ok := s.static[id]
	if !ok {
		return nil, false
	}
	return static, true
}

// AddDynamic adds a dynamic field to display whose value
// is retrieved by running a callback function.
//
// The callback function performs some actions and returns the value
// to display. Generally this is used for calculating requests per
// seconds, elapsed time, etc.
func (s *Statistics) AddDynamic(id string, Callback DynamicCallback) {
	s.dynamic[id] = Callback
}

// GetDynamic returns the dynamic field callback for data retrieval.
func (s *Statistics) GetDynamic(id string) (DynamicCallback, bool) {
	dynamic, ok := s.dynamic[id]
	if !ok {
		return nil, false
	}
	return dynamic, true
}
