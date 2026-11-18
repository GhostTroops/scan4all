package contextutil

import (
	"context"
	"errors"
)

var ErrIncorrectNumberOfItems = errors.New("number of items is not even")

var DefaultContext = context.TODO()

type ContextArg string

// WithValues combines multiple key-value into an existing context
func WithValues(ctx context.Context, keyValue ...ContextArg) (context.Context, error) {
	if len(keyValue)%2 != 0 {
		return ctx, ErrIncorrectNumberOfItems
	}

	for i := 0; i < len(keyValue)-1; i++ {
		ctx = context.WithValue(ctx, keyValue[i], keyValue[i+1]) //nolint
	}
	return ctx, nil
}

// ValueOrDefault returns default context if given is nil (using interface to avoid static check reporting)
func ValueOrDefault(value interface{}) context.Context {
	if ctx, ok := value.(context.Context); ok && ctx != nil {
		return ctx
	}

	return DefaultContext
}
