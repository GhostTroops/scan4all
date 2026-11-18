package errkit

import (
	"errors"
	"log/slog"
)

// Proxy to StdLib errors.Is
func Is(err error, target ...error) bool {
	if err == nil {
		return false
	}
	for i := range target {
		t := target[i]
		if errors.Is(err, t) {
			return true
		}
	}
	return false
}

// IsKind checks if given error is equal to one of the given errkind
// if error did not already have a kind, it tries to parse it
// using default error kinds and given kinds
func IsKind(err error, match ...ErrKind) bool {
	if err == nil {
		return false
	}
	x := &ErrorX{}
	parseError(x, err)
	// try to parse kind from error
	if x.kind == nil {
		// parse kind from error
		tmp := []ErrKind{ErrKindDeadline, ErrKindNetworkPermanent, ErrKindNetworkTemporary}
		tmp = append(tmp, match...)
		x.kind = GetErrorKind(err, tmp...)
	}
	if x.kind != nil {
		if val, ok := x.kind.(*multiKind); ok && len(val.kinds) > 0 {
			// if multi kind return first kind
			for _, kind := range val.kinds {
				for _, k := range match {
					if k.Is(kind) {
						return true
					}
				}
			}
		}
		for _, kind := range match {
			if kind.Is(x.kind) {
				return true
			}
		}
	}
	return false
}

// Proxy to StdLib errors.As
func As(err error, target interface{}) bool {
	return errors.As(err, target)
}

// Combine combines multiple errors into a single error
func Combine(errs ...error) error {
	if len(errs) == 0 {
		return nil
	}
	x := &ErrorX{}
	for _, err := range errs {
		if err == nil {
			continue
		}
		parseError(x, err)
	}
	return x
}

// Wrap wraps the given error with the message
func Wrap(err error, message string) error {
	if err == nil {
		return nil
	}
	x := &ErrorX{}
	parseError(x, err)
	x.Msg(message)
	return x
}

// Wrapf wraps the given error with the message
func Wrapf(err error, format string, args ...interface{}) error {
	if err == nil {
		return nil
	}
	x := &ErrorX{}
	parseError(x, err)
	x.Msgf(format, args...)
	return x
}

// Errors returns all underlying errors there were appended or joined
func Errors(err error) []error {
	if err == nil {
		return nil
	}
	x := &ErrorX{}
	parseError(x, err)
	return x.errs
}

// Append appends given errors and returns a new error
// it ignores all nil errors
func Append(errs ...error) error {
	if len(errs) == 0 {
		return nil
	}
	x := &ErrorX{}
	for _, err := range errs {
		if err == nil {
			continue
		}
		parseError(x, err)
	}
	return x
}

// Join joins given errors and returns a new error
// it ignores all nil errors
// Note: unlike Other libraries, Join does not use `\n`
// so it is equivalent to wrapping/Appending errors
func Join(errs ...error) error {
	return Append(errs...)
}

// Cause returns the original error that caused this error
func Cause(err error) error {
	if err == nil {
		return nil
	}
	x := &ErrorX{}
	parseError(x, err)
	return x.Cause()
}

// WithMessage
func WithMessage(err error, message string) error {
	if err == nil {
		return nil
	}
	x := &ErrorX{}
	parseError(x, err)
	x.Msg(message)
	return x
}

// WithMessagef
func WithMessagef(err error, format string, args ...interface{}) error {
	if err == nil {
		return nil
	}
	x := &ErrorX{}
	parseError(x, err)
	x.Msgf(format, args...)
	return x
}

// IsNetworkTemporaryErr checks if given error is a temporary network error
func IsNetworkTemporaryErr(err error) bool {
	if err == nil {
		return false
	}
	x := &ErrorX{}
	parseError(x, err)
	return isNetworkTemporaryErr(x)
}

// IsDeadlineErr checks if given error is a deadline error
func IsDeadlineErr(err error) bool {
	if err == nil {
		return false
	}
	x := &ErrorX{}
	parseError(x, err)
	return isDeadlineErr(x)
}

// IsNetworkPermanentErr checks if given error is a permanent network error
func IsNetworkPermanentErr(err error) bool {
	if err == nil {
		return false
	}
	x := &ErrorX{}
	parseError(x, err)
	return isNetworkPermanentErr(x)
}

// With adds extra attributes to the error
//
//	err = errkit.With(err,"resource",domain)
func With(err error, args ...any) error {
	if err == nil {
		return nil
	}
	if len(args) == 0 {
		return err
	}
	x := &ErrorX{}
	x.init()
	parseError(x, err)
	x.record.Add(args...)
	return x
}

// WithAttr adds extra attributes to the error using slog.Attr
//
//	err = errkit.WithAttr(err, slog.String("resource", domain))
//	err = errkit.WithAttr(err, slog.Int("port", 80), slog.String("protocol", "tcp"))
func WithAttr(err error, attrs ...slog.Attr) error {
	if err == nil {
		return nil
	}
	if len(attrs) == 0 {
		return err
	}
	x := &ErrorX{}
	x.init()
	parseError(x, err)
	for _, attr := range attrs {
		x.record.Add(attr)
	}
	return x
}

// GetAttr returns all attributes of given error if it has any
func GetAttr(err error) []slog.Attr {
	if err == nil {
		return nil
	}
	x := &ErrorX{}
	parseError(x, err)
	return x.Attrs()
}

// ToSlogAttrGroup returns a slog attribute group for the given error
// it is in format of:
//
//	{
//		"data": {
//			"kind": "<error-kind>",
//			"cause": "<cause>",
//			"errors": [
//				<errs>...
//			]
//		}
//	}
func ToSlogAttrGroup(err error) slog.Attr {
	attrs := ToSlogAttrs(err)
	g := slog.GroupValue(
		attrs..., // append all attrs
	)
	return slog.Any("data", g)
}

// ToSlogAttrs returns slog attributes for the given error
// it is in format of:
//
//	{
//		"kind": "<error-kind>",
//		"cause": "<cause>",
//		"errors": [
//			<errs>...
//		]
//	}
func ToSlogAttrs(err error) []slog.Attr {
	x := &ErrorX{}
	parseError(x, err)
	attrs := []slog.Attr{}
	if x.kind != nil {
		attrs = append(attrs, slog.Any("kind", x.kind.String()))
	}
	if cause := x.Cause(); cause != nil {
		attrs = append(attrs, slog.Any("cause", cause))
	}
	if len(x.errs) > 0 {
		attrs = append(attrs, slog.Any("errors", x.errs))
	}
	return attrs
}

// GetAttrValue returns the value of the attribute with given key
func GetAttrValue(err error, key string) slog.Value {
	if err == nil {
		return slog.Value{}
	}
	x := &ErrorX{}
	parseError(x, err)
	for _, attr := range x.Attrs() {
		if attr.Key == key {
			return attr.Value
		}
	}
	return slog.Value{}
}
