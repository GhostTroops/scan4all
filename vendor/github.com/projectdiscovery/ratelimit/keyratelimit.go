package ratelimit

import (
	"context"
	"sync"
	"time"

	errorutil "github.com/projectdiscovery/utils/errors"
)

var (
	ErrKeyAlreadyExists = errorutil.NewWithTag("MultiLimiter", "key already exists")
	ErrKeyMissing       = errorutil.NewWithTag("MultiLimiter", "key does not exist")
)

// Options of MultiLimiter
type Options struct {
	Key         string // Unique Identifier
	IsUnlimited bool
	MaxCount    uint
	Duration    time.Duration
}

// Validate given MultiLimiter Options
func (o *Options) Validate() error {
	if !o.IsUnlimited {
		if o.Key == "" {
			return errorutil.NewWithTag("MultiLimiter", "empty keys not allowed")
		}
		if o.MaxCount == 0 {
			return errorutil.NewWithTag("MultiLimiter", "maxcount cannot be zero")
		}
		if o.Duration == 0 {
			return errorutil.NewWithTag("MultiLimiter", "time duration not set")
		}
	}
	return nil
}

// MultiLimiter is wrapper around Limiter than can limit based on a key
type MultiLimiter struct {
	limiters sync.Map // map of limiters
	ctx      context.Context
}

// Add new bucket with key
func (m *MultiLimiter) Add(opts *Options) error {
	if err := opts.Validate(); err != nil {
		return err
	}
	var rlimiter *Limiter
	if opts.IsUnlimited {
		rlimiter = NewUnlimited(m.ctx)
	} else {
		rlimiter = New(m.ctx, opts.MaxCount, opts.Duration)
	}
	// ok is true if key already exists
	_, ok := m.limiters.LoadOrStore(opts.Key, rlimiter)
	if ok {
		return ErrKeyAlreadyExists.Msgf("key: %v", opts.Key)
	}
	return nil
}

// GetLimit returns current ratelimit of given key
func (m *MultiLimiter) GetLimit(key string) (uint, error) {
	limiter, err := m.get(key)
	if err != nil {
		return 0, err
	}
	return limiter.GetLimit(), nil
}

// Take one token from bucket returns error if key not present
func (m *MultiLimiter) Take(key string) error {
	limiter, err := m.get(key)
	if err != nil {
		return err
	}
	limiter.Take()
	return nil
}

// CanTake checks if the rate limiter with the given key has any token
func (m *MultiLimiter) CanTake(key string) bool {
	limiter, err := m.get(key)
	if err != nil {
		return false
	}
	return limiter.CanTake()
}

// AddAndTake adds key if not present and then takes token from bucket
func (m *MultiLimiter) AddAndTake(opts *Options) {
	if limiter, err := m.get(opts.Key); err == nil {
		limiter.Take()
		return
	}
	_ = m.Add(opts)
	_ = m.Take(opts.Key)
}

// Stop internal limiters with defined keys or all if no key is provided
func (m *MultiLimiter) Stop(keys ...string) {
	if len(keys) == 0 {
		m.limiters.Range(func(key, value any) bool {
			if limiter, ok := value.(*Limiter); ok {
				limiter.Stop()
			}
			return true
		})
		return
	}
	for _, v := range keys {
		if limiter, err := m.get(v); err == nil {
			limiter.Stop()
		}
	}
}

// get returns *Limiter instance
func (m *MultiLimiter) get(key string) (*Limiter, error) {
	val, _ := m.limiters.Load(key)
	if val == nil {
		return nil, ErrKeyMissing.Msgf("key: %v", key)
	}
	if limiter, ok := val.(*Limiter); ok {
		return limiter, nil
	}
	return nil, errorutil.NewWithTag("MultiLimiter", "type assertion of rateLimiter failed in multiLimiter")
}

// NewMultiLimiter : Limits
func NewMultiLimiter(ctx context.Context, opts *Options) (*MultiLimiter, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	multilimiter := &MultiLimiter{
		ctx:      ctx,
		limiters: sync.Map{},
	}
	return multilimiter, multilimiter.Add(opts)
}
