package disk

import "errors"

var (
	ErrNotImplemented = errors.New("not implemented")
	ErrNotFound       = errors.New("not found")
	ErrNoData         = errors.New("no data")
)
