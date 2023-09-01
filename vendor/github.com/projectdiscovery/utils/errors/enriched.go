package errorutil

import (
	"bytes"
	"fmt"
	"runtime/debug"
	"strings"
)

// ShowStackTrace in Error Message
var ShowStackTrace bool = false

// ErrCallback function to handle given error
type ErrCallback func(level ErrorLevel, err string, tags ...string)

// enrichedError is enriched version of normal error
// with tags, stacktrace and other methods
type enrichedError struct {
	errString  string
	StackTrace string
	Tags       []string
	Level      ErrorLevel

	//OnError is called when Error() method is triggered
	OnError ErrCallback
}

// withTag assignes tag to Error
func (e *enrichedError) WithTag(tag ...string) Error {
	if e.Tags == nil {
		e.Tags = tag
	} else {
		e.Tags = append(e.Tags, tag...)
	}
	return e
}

// withLevel assinges level to Error
func (e *enrichedError) WithLevel(level ErrorLevel) Error {
	e.Level = level
	return e
}

// returns formated *enrichedError string
func (e *enrichedError) Error() string {
	defer func() {
		if e.OnError != nil {
			e.OnError(e.Level, e.errString, e.Tags...)
		}
	}()
	var buff bytes.Buffer
	label := fmt.Sprintf("[%v:%v]", strings.Join(e.Tags, ","), e.Level.String())
	buff.WriteString(fmt.Sprintf("%v %v", label, e.errString))

	if ShowStackTrace {
		e.captureStack()
		buff.WriteString(fmt.Sprintf("Stacktrace:\n%v", e.StackTrace))
	}
	return buff.String()
}

// wraps given error
func (e *enrichedError) Wrap(err ...error) Error {
	for _, v := range err {
		if v == nil {
			continue
		}
		if ee, ok := v.(*enrichedError); ok {
			_ = e.Msgf(ee.errString).WithLevel(ee.Level).WithTag(ee.Tags...)
			e.StackTrace += ee.StackTrace
		} else {
			_ = e.Msgf(v.Error())
		}
	}
	return e
}

// Wrapf wraps given message
func (e *enrichedError) Msgf(format string, args ...any) Error {
	// wraps with '<-` as delimeter
	msg := fmt.Sprintf(format, args...)
	if e.errString == "" {
		e.errString = msg
	} else {
		e.errString = fmt.Sprintf("%v <- %v", msg, e.errString)
	}
	return e
}

// Equal returns true if error matches anyone of given errors
func (e *enrichedError) Equal(err ...error) bool {
	for _, v := range err {
		if ee, ok := v.(*enrichedError); ok {
			if e.errString == ee.errString {
				return true
			}
		} else {
			// not an enriched error but a simple eror
			if e.errString == v.Error() {
				return true
			}
		}
	}
	return false
}

// WithCallback executes callback when error is triggered
func (e *enrichedError) WithCallback(handle ErrCallback) Error {
	e.OnError = handle
	return e
}

// captureStack
func (e *enrichedError) captureStack() {
	// can be furthur improved to format
	// ref https://github.com/go-errors/errors/blob/33d496f939bc762321a636d4035e15c302eb0b00/stackframe.go
	e.StackTrace = string(debug.Stack())
}

// New
func New(format string, args ...any) Error {
	ee := &enrichedError{
		errString: fmt.Sprintf(format, args...),
		Level:     Runtime,
	}
	return ee
}

func NewWithErr(err error) Error {
	if err == nil {
		return nil
	}
	if ee, ok := err.(*enrichedError); ok {
		x := New(ee.errString).WithTag(ee.Tags...).WithLevel(ee.Level)
		x.(*enrichedError).StackTrace = ee.StackTrace
	}
	return New(err.Error())
}

// NewWithTag creates an error with tag
func NewWithTag(tag string, format string, args ...any) Error {
	ee := New(format, args...)
	_ = ee.WithTag(tag)
	return ee
}
