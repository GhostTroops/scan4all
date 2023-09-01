package ratelimit

import (
	"context"
	"math"
	"sync/atomic"
	"time"
)

// equals to -1
var minusOne = ^uint32(0)

// Limiter allows a burst of request during the defined duration
type Limiter struct {
	maxCount uint32
	count    atomic.Uint32
	ticker   *time.Ticker
	tokens   chan struct{}
	ctx      context.Context
	// internal
	cancelFunc context.CancelFunc
}

func (limiter *Limiter) run(ctx context.Context) {
	defer close(limiter.tokens)
	for {
		if limiter.count.Load() == 0 {
			<-limiter.ticker.C
			limiter.count.Store(limiter.maxCount)
		}
		select {
		case <-ctx.Done():
			// Internal Context
			limiter.ticker.Stop()
			return
		case <-limiter.ctx.Done():
			limiter.ticker.Stop()
			return
		case limiter.tokens <- struct{}{}:
			limiter.count.Add(minusOne)
		case <-limiter.ticker.C:
			limiter.count.Store(limiter.maxCount)
		}
	}
}

// Take one token from the bucket
func (limiter *Limiter) Take() {
	<-limiter.tokens
}

// CanTake checks if the rate limiter has any token
func (limiter *Limiter) CanTake() bool {
	return limiter.count.Load() > 0
}

// GetLimit returns current rate limit per given duration
func (limiter *Limiter) GetLimit() uint {
	return uint(limiter.maxCount)
}

// TODO: SleepandReset should be able to handle multiple calls without resetting multiple times
// Which is not possible in this implementation
// // SleepandReset stops timer removes all tokens and resets with new limit (used for Adaptive Ratelimiting)
// func (ratelimiter *Limiter) SleepandReset(sleepTime time.Duration, newLimit uint, duration time.Duration) {
// 	// stop existing Limiter using internalContext
// 	ratelimiter.cancelFunc()
// 	// drain any token
// 	close(ratelimiter.tokens)
// 	<-ratelimiter.tokens
// 	// sleep
// 	time.Sleep(sleepTime)
// 	//reset and start
// 	ratelimiter.maxCount = newLimit
// 	ratelimiter.count = newLimit
// 	ratelimiter.ticker = time.NewTicker(duration)
// 	ratelimiter.tokens = make(chan struct{})
// 	ctx, cancel := context.WithCancel(context.TODO())
// 	ratelimiter.cancelFunc = cancel
// 	go ratelimiter.run(ctx)
// }

// Stop the rate limiter canceling the internal context
func (limiter *Limiter) Stop() {
	if limiter.cancelFunc != nil {
		limiter.cancelFunc()
	}
}

// New creates a new limiter instance with the tokens amount and the interval
func New(ctx context.Context, max uint, duration time.Duration) *Limiter {
	internalctx, cancel := context.WithCancel(context.TODO())

	limiter := &Limiter{
		maxCount:   uint32(max),
		ticker:     time.NewTicker(duration),
		tokens:     make(chan struct{}),
		ctx:        ctx,
		cancelFunc: cancel,
	}
	limiter.count.Store(uint32(max))
	go limiter.run(internalctx)

	return limiter
}

// NewUnlimited create a bucket with approximated unlimited tokens
func NewUnlimited(ctx context.Context) *Limiter {
	internalctx, cancel := context.WithCancel(context.TODO())

	limiter := &Limiter{
		maxCount:   math.MaxUint32,
		ticker:     time.NewTicker(time.Millisecond),
		tokens:     make(chan struct{}),
		ctx:        ctx,
		cancelFunc: cancel,
	}
	limiter.count.Store(math.MaxUint32)
	go limiter.run(internalctx)

	return limiter
}
