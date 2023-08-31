package errorutil

// Error is enriched version of normal error
// with tags, stacktrace and other methods
type Error interface {
	// WithTag assigns tag[s] to Error
	WithTag(tag ...string) Error
	// WithLevel assigns given ErrorLevel
	WithLevel(level ErrorLevel) Error
	// Error is interface method of 'error'
	Error() string
	// Wraps existing error with errors (skips if passed error is nil)
	Wrap(err ...error) Error
	// Msgf wraps error with given message
	Msgf(format string, args ...any) Error
	// Equal Checks Equality of errors
	Equal(err ...error) bool
	// WithCallback execute ErrCallback function when Error is triggered
	WithCallback(handle ErrCallback) Error
}
