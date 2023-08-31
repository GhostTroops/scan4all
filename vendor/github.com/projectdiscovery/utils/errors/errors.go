package errorutil

import (
	"fmt"
	"strings"
)

// IsAny checks if err is not nil and matches any one of errxx errors
// if match successful returns true else false
// Note: no unwrapping is done here
func IsAny(err error, errxx ...error) bool {
	if err == nil {
		return false
	}
	if enrichedErr, ok := err.(Error); ok {
		for _, v := range errxx {
			if enrichedErr.Equal(v) {
				return true
			}
		}
	} else {
		for _, v := range errxx {
			// check if v is an enriched error
			if ee, ok := v.(Error); ok && ee.Equal(err) {
				return true
			}
			// check standard error equality
			if strings.EqualFold(err.Error(), fmt.Sprint(v)) {
				return true
			}
		}
	}
	return false
}

// WrapfWithNil returns nil if error is nil but if err is not nil
// wraps error with given msg unlike errors.Wrapf
func WrapfWithNil(err error, format string, args ...any) Error {
	if err == nil {
		return nil
	}
	ee := NewWithErr(err)
	return ee.Msgf(format, args...)
}

// WrapwithNil returns nil if err is nil but wraps it with given
// errors continuously if it is not nil
func WrapwithNil(err error, errx ...error) Error {
	if err == nil {
		return nil
	}
	ee := NewWithErr(err)
	return ee.Wrap(errx...)
}
