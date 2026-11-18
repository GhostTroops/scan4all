// Package errorutil provides error handling utilities.
//
// Deprecated: This package is deprecated and will be removed in a future version.
// Use github.com/projectdiscovery/utils/errkit instead.
package errorutil

// Error is enriched version of normal error
// with tags and other methods
//
// Deprecated: Use errkit.ErrorX instead.
type Error interface {
	// WithTag assigns tag[s] to Error
	//
	// Deprecated: Use errkit.ErrorX instead.
	WithTag(tag ...string) Error
	// WithLevel assigns given ErrorLevel
	//
	// Deprecated: Use errkit.ErrorX instead.
	WithLevel(level ErrorLevel) Error
	// Error is interface method of 'error'
	//
	// Deprecated: Use errkit.ErrorX instead.
	Error() string
	// Unwrap returns the underlying error
	//
	// Deprecated: Use errkit.ErrorX instead.
	Unwrap() error
	// Wraps existing error with errors (skips if passed error is nil)
	//
	// Deprecated: Use errkit.ErrorX instead.
	Wrap(err ...error) Error
	// Msgf wraps error with given message
	//
	// Deprecated: Use errkit.ErrorX instead.
	Msgf(format string, args ...any) Error
	// Equal Checks Equality of errors
	//
	// Deprecated: Use errkit.ErrorX instead.
	Equal(err ...error) bool
	// WithCallback execute ErrCallback function when Error is triggered
	//
	// Deprecated: Use errkit.ErrorX instead.
	WithCallback(handle ErrCallback) Error
}
