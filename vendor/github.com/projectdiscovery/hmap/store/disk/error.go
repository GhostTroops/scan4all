package disk

import "github.com/pkg/errors"

var (
	ErrNotImplemented = errors.New("not implemented")
	ErrNotFound       = errors.New("not found")
	ErrNoData         = errors.New("no data")
	ErrNotSupported   = errors.New("not supported")
)
