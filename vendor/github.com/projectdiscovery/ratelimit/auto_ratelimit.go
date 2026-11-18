package ratelimit

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrAutoKeyAlreadyExists = errors.New("key already exists")
	ErrAutoKeyMissing       = errors.New("key does not exist")
)

// AutoLimiterOption is a function that configures the AutoLimiter
type AutoLimiterOption func(*AutoLimiter)

// WithUnlimited sets the limiter to unlimited mode
func WithUnlimited() AutoLimiterOption {
	return func(e *AutoLimiter) {
		e.defaultOptions.IsUnlimited = true
	}
}

// WithDuration sets the duration for the rate limiter
func WithDuration(duration time.Duration) AutoLimiterOption {
	return func(e *AutoLimiter) {
		e.defaultOptions.Duration = duration
	}
}

// WithMaxCount sets the maximum count for the rate limiter
func WithMaxCount(maxCount uint) AutoLimiterOption {
	return func(e *AutoLimiter) {
		e.defaultOptions.MaxCount = maxCount
	}
}

// AutoLimiter is an improved version of MultiLimiter with better memory management
type AutoLimiter struct {
	limiters sync.Map // map of active limiters
	options  sync.Map // map of custom options (only for keys with custom settings)
	ctx      context.Context

	// Default options for automatically created limiters
	defaultOptions *internalOptions
}

// NewAutoLimiter creates a new auto limiter instance using functional options
func NewAutoLimiter(ctx context.Context, opts ...AutoLimiterOption) *AutoLimiter {
	e := &AutoLimiter{
		ctx:            ctx,
		limiters:       sync.Map{},
		options:        sync.Map{},
		defaultOptions: &internalOptions{},
	}

	// Apply all options to set the defaults
	for _, opt := range opts {
		opt(e)
	}

	return e
}

// internalOptions holds configuration internally (not exposed to users)
type internalOptions struct {
	Key         string
	IsUnlimited bool
	MaxCount    uint
	Duration    time.Duration
}

// Validate internal options
func (o *internalOptions) Validate() error {
	if !o.IsUnlimited {
		if o.Key == "" {
			return errors.New("empty keys not allowed")
		}
		if o.MaxCount == 0 {
			return errors.New("maxcount cannot be zero")
		}
		if o.Duration == 0 {
			return errors.New("time duration not set")
		}
	}
	return nil
}

// Add creates a new rate limiter with custom settings (only for keys that need specific limits)
func (e *AutoLimiter) Add(key string, opts ...AutoLimiterOption) error {
	// Create options struct and apply functional options to it
	options := &internalOptions{Key: key}

	// Apply all options to the options struct
	for _, opt := range opts {
		// Create a temporary limiter to apply the option
		tempLimiter := &AutoLimiter{defaultOptions: options}
		opt(tempLimiter)
	}

	// Validate the configuration
	if !options.IsUnlimited {
		if key == "" {
			return errors.New("empty keys not allowed")
		}
		if options.MaxCount == 0 {
			return errors.New("maxcount cannot be zero")
		}
		if options.Duration == 0 {
			return errors.New("time duration not set")
		}
	}

	// Check if key already exists
	if _, exists := e.limiters.Load(key); exists {
		return ErrAutoKeyAlreadyExists
	}

	// Create new limiter with custom settings
	var rlimiter *Limiter
	if options.IsUnlimited {
		rlimiter = NewUnlimited(e.ctx)
	} else {
		rlimiter = New(e.ctx, options.MaxCount, options.Duration)
	}

	// Store the limiter and options
	e.limiters.Store(key, rlimiter)
	e.options.Store(key, options)

	return nil
}

// Take one token from bucket - creates limiter automatically if it doesn't exist
func (e *AutoLimiter) Take(key string) error {
	limiter, err := e.get(key)
	if err != nil {
		// Key doesn't exist, create it with default settings
		limiter = e.createOrDefault(key)
	}
	limiter.Take()
	return nil
}

// Stop internal limiters with defined keys or all if no key is provided
func (e *AutoLimiter) Stop(keys ...string) {
	if len(keys) == 0 {
		e.limiters.Range(func(key, value any) bool {
			if limiter, ok := value.(*Limiter); ok {
				limiter.Stop()
				e.limiters.Delete(key)
				// Keep the options for potential recreation
			}
			return true
		})
		return
	}
	for _, v := range keys {
		if limiter, err := e.get(v); err == nil {
			limiter.Stop()
			e.limiters.Delete(v)
			// Keep the options for potential recreation
		}
	}
}

// Remove completely removes a key and its options
func (e *AutoLimiter) Remove(key string) {
	// Stop and remove the limiter if it exists
	if limiter, err := e.get(key); err == nil {
		limiter.Stop()
		e.limiters.Delete(key)
	}
	// Remove the stored options
	e.options.Delete(key)
}

// get returns *Limiter instance
func (e *AutoLimiter) get(key string) (*Limiter, error) {
	val, _ := e.limiters.Load(key)
	if val == nil {
		return nil, ErrAutoKeyMissing
	}
	if limiter, ok := val.(*Limiter); ok {
		return limiter, nil
	}
	return nil, errors.New("type assertion of rateLimiter failed in autoLimiter")
}

// recreateLimiter recreates a limiter from stored options
func (e *AutoLimiter) recreateLimiter(key string) (*Limiter, error) {
	// Check if we have stored options for this key
	optsVal, exists := e.options.Load(key)
	if !exists {
		return nil, ErrAutoKeyMissing
	}

	opts, ok := optsVal.(*internalOptions)
	if !ok {
		return nil, errors.New("invalid options type")
	}

	// Create new limiter with stored options
	var rlimiter *Limiter
	if opts.IsUnlimited {
		rlimiter = NewUnlimited(e.ctx)
	} else {
		rlimiter = New(e.ctx, opts.MaxCount, opts.Duration)
	}

	// Store the new limiter
	e.limiters.Store(key, rlimiter)

	return rlimiter, nil
}

// createOrDefault creates a new limiter with default settings
func (e *AutoLimiter) createOrDefault(key string) *Limiter {
	// First check if we have stored custom options for this key
	if optsVal, exists := e.options.Load(key); exists {
		if _, ok := optsVal.(*internalOptions); ok {
			// Recreate with stored custom options
			if limiter, err := e.recreateLimiter(key); err == nil {
				return limiter
			}
			// If recreation fails, fall back to defaults
		}
	}

	// No custom options, create with stored default options
	var limiter *Limiter
	if e.defaultOptions.IsUnlimited {
		limiter = NewUnlimited(e.ctx)
	} else {
		limiter = New(e.ctx, e.defaultOptions.MaxCount, e.defaultOptions.Duration)
	}

	// Store the limiter
	e.limiters.Store(key, limiter)

	// Note: We don't store options for default limiters since they can be recreated
	// Only custom limiters (added via Add()) get their options stored

	return limiter
}

// AddAndTake adds a key with custom settings if not present and then takes a token
func (e *AutoLimiter) AddAndTake(key string, opts ...AutoLimiterOption) error {
	// Check if limiter already exists
	if limiter, err := e.get(key); err == nil {
		limiter.Take()
		return nil
	}

	// Add the key with custom settings
	if err := e.Add(key, opts...); err != nil {
		return err
	}

	// Take a token
	return e.Take(key)
}
