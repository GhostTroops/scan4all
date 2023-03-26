package go_utils

import (
	"github.com/panjf2000/ants/v2"
	"time"
)

const (
	// DefaultAntsPoolSize sets up the capacity of worker pool, 256 * 1024.
	DefaultAntsPoolSize = 1 << 18

	// ExpiryDuration is the interval time to clean up those expired workers.
	ExpiryDuration = 10 * time.Second

	// Nonblocking decides what to do when submitting a new task to a full worker pool: waiting for a available worker
	// or returning nil directly.
	Nonblocking = true
)

// Pool is the alias of ants.Pool.
type Pool = ants.Pool

type MyPool struct {
	*ants.Pool
}

func (r *MyPool) Submit(cbk func()) {
	Wg.Add(1)
	r.Pool.Submit(func() {
		defer Wg.Done()
		cbk()
	})
}

var DefaultPool *MyPool

func create() *MyPool {
	options := ants.Options{ExpiryDuration: ExpiryDuration, Nonblocking: Nonblocking}
	defaultAntsPool, _ := ants.NewPool(GetValAsInt("DefaultAntsPoolSize", 2000), ants.WithOptions(options), ants.WithNonblocking(true))
	return &MyPool{defaultAntsPool}
}

func init() {
	RegInitFunc4Hd(func() {
		// It releases the default pool from ants.
		ants.Release()
		DefaultPool = create()
	})
}
