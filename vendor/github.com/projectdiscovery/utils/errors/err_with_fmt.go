// Package errorutil provides error handling utilities.
//
// Deprecated: This package is deprecated and will be removed in a future version.
// Use github.com/projectdiscovery/utils/errkit instead.
package errorutil

import (
	"fmt"
)

// ErrWithFmt is a simplified version of err holding a default format
//
// Deprecated: Use errkit.ErrorX instead.
type ErrWithFmt struct {
	fmt string
}

// Msgf wraps given message
//
// Deprecated: Use errkit.ErrorX instead.
func (e *ErrWithFmt) Msgf(args ...any) error {
	return fmt.Errorf(e.fmt, args...)
}

// Error implements error interface
//
// Deprecated: Use errkit.ErrorX instead.
func (e *ErrWithFmt) Error() {
	panic("ErrWithFmt is a format holder")
}

// NewWithFmt creates a new ErrWithFmt
//
// Deprecated: Use errkit.New instead.
func NewWithFmt(fmt string) ErrWithFmt {
	if fmt == "" {
		panic("format can't be empty")
	}

	return ErrWithFmt{fmt: fmt}
}
