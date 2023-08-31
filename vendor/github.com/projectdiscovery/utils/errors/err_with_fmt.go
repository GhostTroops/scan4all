package errorutil

import (
	"fmt"
)

// ErrWithFmt is a simplified version of err holding a default format
type ErrWithFmt struct {
	fmt string
}

// Wrapf wraps given message
func (e *ErrWithFmt) Msgf(args ...any) error {
	return fmt.Errorf(e.fmt, args...)
}

func (e *ErrWithFmt) Error() {
	panic("ErrWithFmt is a format holder")
}

func NewWithFmt(fmt string) ErrWithFmt {
	if fmt == "" {
		panic("format can't be empty")
	}

	return ErrWithFmt{fmt: fmt}
}
