// Package errorutil provides error handling utilities.
//
// Deprecated: This package is deprecated and will be removed in a future version.
// Use github.com/projectdiscovery/utils/errkit instead, which provides better
// error handling with proper Go error chain support and optional stack traces.
package errorutil

import (
	"errors"

	"github.com/projectdiscovery/utils/errkit"
)

// ErrCallback function to handle given error
//
// Deprecated: Use errkit.ErrorX and its structured logging capabilities instead.
type ErrCallback func(level ErrorLevel, err string, tags ...string)

// enrichedError is enriched version of normal error
// with tags and other methods
//
// Deprecated: Use errkit.ErrorX instead.
type enrichedError struct {
	errorX      *errkit.ErrorX
	level       ErrorLevel
	tags        []string
	callback    ErrCallback
	wrappedErrs []error // Keep original errors for compatibility
}

// WithTag assignes tag to Error
//
// Deprecated: Use errkit.ErrorX instead.
func (e *enrichedError) WithTag(tag ...string) Error {
	if e.tags == nil {
		e.tags = tag
	} else {
		e.tags = append(e.tags, tag...)
	}
	return e
}

// WithLevel assinges level to Error
//
// Deprecated: Use errkit.ErrorX instead.
func (e *enrichedError) WithLevel(level ErrorLevel) Error {
	e.level = level
	return e
}

// Unwrap returns the underlying error
//
// Deprecated: Use errkit.ErrorX instead.
func (e *enrichedError) Unwrap() error {
	if e.errorX != nil {
		// Return the original error that was used to create this enrichedError
		return e.errorX.Cause()
	}
	return nil
}

// Error returns formatted *enrichedError string
//
// Deprecated: Use errkit.ErrorX instead.
func (e *enrichedError) Error() string {
	defer func() {
		if e.callback != nil {
			errStr := ""
			if e.errorX != nil {
				errStr = e.errorX.Error()
			}
			e.callback(e.level, errStr, e.tags...)
		}
	}()

	if e.errorX == nil {
		return ""
	}

	return e.errorX.Error()
}

// Wrap wraps given error
//
// Deprecated: Use errkit.ErrorX instead.
func (e *enrichedError) Wrap(err ...error) Error {
	for _, v := range err {
		if v == nil {
			continue
		}

		// Store original error for compatibility
		e.wrappedErrs = append(e.wrappedErrs, v)

		if e.errorX == nil {
			// Create a new ErrorX starting with this error
			e.errorX = errkit.FromError(v)
		} else {
			// Add this error to the existing ErrorX
			e.errorX.Msgf("%s", v.Error())
		}
	}

	return e
}

// Msgf wraps given message
//
// Deprecated: Use errkit.ErrorX instead.
func (e *enrichedError) Msgf(format string, args ...any) Error {
	if e.errorX == nil {
		e.errorX = errkit.New("error")
	}
	// Pass format and args directly to errkit.Msgf
	e.errorX.Msgf(format, args...)
	return e
}

// Equal returns true if error matches anyone of given errors
//
// Deprecated: Use errkit.ErrorX instead.
func (e *enrichedError) Equal(err ...error) bool {
	for _, v := range err {
		if e.Is(v) {
			return true
		}
	}
	return false
}

// Is implements the errors.Is interface for Go's error chain traversal
func (e *enrichedError) Is(target error) bool {
	// First check our wrapped errors for exact matches
	for _, wrappedErr := range e.wrappedErrs {
		if errors.Is(wrappedErr, target) {
			return true
		}
	}
	
	// Then check errkit's Is method
	if e.errorX != nil {
		return e.errorX.Is(target)
	}
	
	return false
}

// WithCallback executes callback when error is triggered
//
// Deprecated: Use errkit.ErrorX instead.
func (e *enrichedError) WithCallback(handle ErrCallback) Error {
	e.callback = handle
	return e
}

// New creates a new error
//
// Deprecated: Use errkit.New instead.
func New(format string, args ...any) Error {
	errorX := errkit.New(format, args...)
	ee := &enrichedError{
		errorX: errorX,
		level:  Runtime,
	}
	return ee
}

// NewWithErr creates a new error with an existing error
//
// Deprecated: Use errkit.FromError instead.
func NewWithErr(err error) Error {
	if err == nil {
		return nil
	}

	if ee, ok := err.(*enrichedError); ok {
		return &enrichedError{
			errorX:      ee.errorX,
			level:       ee.level,
			tags:        append([]string{}, ee.tags...),
			callback:    ee.callback,
			wrappedErrs: append([]error{}, ee.wrappedErrs...),
		}
	}

	errorX := errkit.FromError(err)
	return &enrichedError{
		errorX:      errorX,
		level:       Runtime,
		wrappedErrs: []error{err}, // Store the original error
	}
}

// NewWithTag creates an error with tag
//
// Deprecated: Use errkit.New instead.
func NewWithTag(tag string, format string, args ...any) Error {
	ee := New(format, args...)
	_ = ee.WithTag(tag)
	return ee
}