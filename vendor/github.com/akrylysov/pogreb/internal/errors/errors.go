package errors

import (
	"errors"
	"fmt"
)

type wrappedError struct {
	cause error
	msg   string
}

func (we wrappedError) Error() string {
	return we.msg + ": " + we.cause.Error()
}

func (we wrappedError) Unwrap() error {
	return we.cause
}

// New returns an error that formats as the given text.
func New(text string) error {
	return errors.New(text)
}

// Wrap returns an error annotating err with an additional message.
// Compatible with Go 1.13 error chains.
func Wrap(cause error, message string) error {
	return wrappedError{
		cause: cause,
		msg:   message,
	}
}

// Wrapf returns an error annotating err with an additional formatted message.
// Compatible with Go 1.13 error chains.
func Wrapf(cause error, format string, a ...interface{}) error {
	return wrappedError{
		cause: cause,
		msg:   fmt.Sprintf(format, a...),
	}
}
