package go_utils

import (
	"context"
	"math"
	"sync"
)

// SizedWaitGroup has the same role and close to the
// same API as the Golang sync.WaitGroup but adds a limit of
// the amount of goroutines started concurrently.
type SizedWaitGroup struct {
	Size int

	current chan struct{}
	*sync.WaitGroup
}

// New creates a SizedWaitGroup.
// The limit parameter is the maximum amount of
// goroutines which can be started concurrently.
func NewSizedWaitGroup(limit int) SizedWaitGroup {
	size := math.MaxInt32 // 2^31 - 1
	if limit > 0 {
		size = limit
	}
	rt := SizedWaitGroup{
		Size:    size,
		current: make(chan struct{}, size),
	}
	rt.WaitGroup = &sync.WaitGroup{}
	return rt
}

func (s *SizedWaitGroup) Add(delta int) {
	for i := 0; i < delta; i++ {
		s.AddWithContext(context.Background())
	}
}

// AddWithContext increments the internal WaitGroup counter.
// It can be blocking if the limit of spawned goroutines
// has been reached. It will stop blocking when Done is
// been called, or when the context is canceled. Returns nil on
// success or an error if the context is canceled before the lock
// is acquired.
//
// See sync.WaitGroup documentation for more information.
func (s *SizedWaitGroup) AddWithContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case s.current <- struct{}{}:
		break
	}
	s.WaitGroup.Add(1)
	return nil
}

// Done decrements the SizedWaitGroup counter.
// See sync.WaitGroup documentation for more information.
func (s *SizedWaitGroup) Done() {
	<-s.current
	s.WaitGroup.Done()
}

// Wait blocks until the SizedWaitGroup counter is zero.
// See sync.WaitGroup documentation for more information.
func (s *SizedWaitGroup) Wait() {
	s.WaitGroup.Wait()
}

func (s *SizedWaitGroup) WaitLen() int {
	return len(s.current)
}
