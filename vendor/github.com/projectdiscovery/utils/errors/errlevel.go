// Package errorutil provides error handling utilities.
//
// Deprecated: This package is deprecated and will be removed in a future version.
// Use github.com/projectdiscovery/utils/errkit instead.
package errorutil

// ErrorLevel represents the severity level of an error
//
// Deprecated: Use errkit.ErrKind instead.
type ErrorLevel uint

const (
	// Panic level error
	//
	// Deprecated: Use errkit.ErrKind instead.
	Panic ErrorLevel = iota
	// Fatal level error
	//
	// Deprecated: Use errkit.ErrKind instead.
	Fatal
	// Runtime level error (Default)
	//
	// Deprecated: Use errkit.ErrKind instead.
	Runtime
)

// String returns string representation of ErrorLevel
//
// Deprecated: Use errkit.ErrKind instead.
func (l ErrorLevel) String() string {
	switch l {
	case Panic:
		return "PANIC"
	case Fatal:
		return "FATAL"
	case Runtime:
		return "RUNTIME"
	}
	return "RUNTIME" //default is runtime
}
