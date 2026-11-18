// Package errorutil provides error handling utilities.
//
// Deprecated: This package is deprecated and will be removed in a future version.
// Use github.com/projectdiscovery/utils/errkit instead.
package errorutil

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

// IsAny checks if err is not nil and matches any one of errxx errors
// if match successful returns true else false
//
// Deprecated: Use standard library errors.Is instead.
func IsAny(err error, errxx ...error) bool {
	if err == nil {
		return false
	}

	for _, v := range errxx {
		if v == nil {
			continue
		}

		// Use stdlib errors.Is for proper err chain traversal
		// NOTE(dwisiswant0): Check both directions since either error could
		// wrap the other
		if errors.Is(err, v) || errors.Is(v, err) {
			return true
		}

		// also check enriched error equality (backward-compatible)
		if enrichedErr, ok := err.(Error); ok {
			if enrichedErr.Equal(v) {
				return true
			}
		}

		// fallback to str cmp for non-enriched errors
		if strings.EqualFold(err.Error(), fmt.Sprint(v)) {
			return true
		}
	}
	return false
}

// WrapfWithNil returns nil if error is nil but if err is not nil
// wraps error with given msg unlike errors.Wrapf
//
// Deprecated: Use errkit.FromError instead.
func WrapfWithNil(err error, format string, args ...any) Error {
	if err == nil {
		return nil
	}
	ee := NewWithErr(err)
	return ee.Msgf(format, args...)
}

// WrapwithNil returns nil if err is nil but wraps it with given
// errors continuously if it is not nil
//
// Deprecated: Use errkit.FromError instead.
func WrapwithNil(err error, errx ...error) Error {
	if err == nil {
		return nil
	}
	ee := NewWithErr(err)
	return ee.Wrap(errx...)
}

// IsTimeout checks if error is timeout error
//
// Deprecated: Use standard library errors.Is with context.DeadlineExceeded instead.
func IsTimeout(err error) bool {
	var net net.Error
	return (errors.As(err, &net) && net.Timeout()) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded)
}
