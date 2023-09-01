package generic

import (
	"sync"
)

type Lockable[K any] struct {
	V K
	sync.RWMutex
}

func (v *Lockable[K]) Do(f func(val K)) {
	v.Lock()
	defer v.Unlock()
	f(v.V)
}

func WithLock[K any](val K) *Lockable[K] {
	return &Lockable[K]{V: val}
}
