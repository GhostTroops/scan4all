package errkit

import (
	"context"
	"errors"
	"os"
	"strings"

	"golang.org/x/exp/maps"
)

var (
	// ErrClassNetwork indicates an error related to network operations
	// these may be resolved by retrying the operation with exponential backoff
	// ex: Timeout awaiting headers, i/o timeout etc
	ErrKindNetworkTemporary = NewPrimitiveErrKind("network-temporary-error", "temporary network error", isNetworkTemporaryErr)
	// ErrKindNetworkPermanent indicates a permanent error related to network operations
	// these may not be resolved by retrying and need manual intervention
	// ex: no address found for host
	ErrKindNetworkPermanent = NewPrimitiveErrKind("network-permanent-error", "permanent network error", isNetworkPermanentErr)
	// ErrKindDeadline indicates a timeout error in logical operations
	// these are custom deadlines set by nuclei itself to prevent infinite hangs
	// and in most cases are server side issues (ex: server connects but does not respond at all)
	// a manual intervention is required
	ErrKindDeadline = NewPrimitiveErrKind("deadline-error", "deadline error", isDeadlineErr)
	// ErrKindUnknown indicates an unknown error class
	// that has not been implemented yet this is used as fallback when converting a slog Item
	ErrKindUnknown = NewPrimitiveErrKind("unknown-error", "unknown error", nil)
)

var (
	// DefaultErrorKinds is the default error kinds used in classification
	// if one intends to add more default error kinds it must be done in init() function
	// of that package to avoid race conditions
	DefaultErrorKinds = []ErrKind{
		ErrKindNetworkTemporary,
		ErrKindNetworkPermanent,
		ErrKindDeadline,
	}
)

// ErrKind is an interface that represents a kind of error
type ErrKind interface {
	// Is checks if current error kind is same as given error kind
	Is(ErrKind) bool
	// IsParent checks if current error kind is parent of given error kind
	// this allows heirarchical classification of errors and app specific handling
	IsParent(ErrKind) bool
	// RepresentsError checks if given error is of this kind
	Represents(*ErrorX) bool
	// Description returns predefined description of the error kind
	// this can be used to show user friendly error messages in case of error
	Description() string
	// String returns the string representation of the error kind
	String() string
}

var _ ErrKind = &primitiveErrKind{}

// primitiveErrKind is kind of error used in classification
type primitiveErrKind struct {
	id         string
	info       string
	represents func(*ErrorX) bool
}

func (e *primitiveErrKind) Is(kind ErrKind) bool {
	return e.id == kind.String()
}

func (e *primitiveErrKind) IsParent(kind ErrKind) bool {
	return false
}

func (e *primitiveErrKind) Represents(err *ErrorX) bool {
	if e.represents != nil {
		return e.represents(err)
	}
	return false
}

func (e *primitiveErrKind) String() string {
	return e.id
}

func (e *primitiveErrKind) Description() string {
	return e.info
}

// NewPrimitiveErrKind creates a new primitive error kind
func NewPrimitiveErrKind(id string, info string, represents func(*ErrorX) bool) ErrKind {
	p := &primitiveErrKind{id: id, info: info, represents: represents}
	return p
}

func isNetworkTemporaryErr(err *ErrorX) bool {
	if err.Cause() != nil {
		return os.IsTimeout(err.Cause())
	}
	v := err.Cause()
	switch {
	case os.IsTimeout(v):
		return true
	case strings.Contains(v.Error(), "Client.Timeout exceeded while awaiting headers"):
		return true
	}
	return false
}

// isNetworkPermanentErr checks if given error is a permanent network error
func isNetworkPermanentErr(err *ErrorX) bool {
	if err.Cause() == nil {
		return false
	}
	v := err.Cause().Error()
	// to implement
	switch {
	case strings.Contains(v, "no address found"):
		return true
	case strings.Contains(v, "no such host"):
		return true
	case strings.Contains(v, "could not resolve host"):
		return true
	case strings.Contains(v, "port closed or filtered"):
		// pd standard error for port closed or filtered
		return true
	case strings.Contains(v, "connect: connection refused"):
		return true
	case strings.Contains(v, "Unable to connect"):
		// occurs when HTTP(S) proxy is used
		return true
	case strings.Contains(v, "host unreachable"):
		// occurs when SOCKS proxy is used
		return true
	}
	return false
}

// isDeadlineErr checks if given error is a deadline error
func isDeadlineErr(err *ErrorX) bool {
	// to implement
	if err.Cause() == nil {
		return false
	}
	v := err.Cause()
	switch {
	case errors.Is(v, os.ErrDeadlineExceeded):
		return true
	case errors.Is(v, context.DeadlineExceeded):
		return true
	case errors.Is(v, context.Canceled):
		return true
	}

	return false
}

type multiKind struct {
	kinds []ErrKind
}

func (e *multiKind) Is(kind ErrKind) bool {
	for _, k := range e.kinds {
		if k.Is(kind) {
			return true
		}
	}
	return false
}

func (e *multiKind) IsParent(kind ErrKind) bool {
	for _, k := range e.kinds {
		if k.IsParent(kind) {
			return true
		}
	}
	return false
}

func (e *multiKind) Represents(err *ErrorX) bool {
	for _, k := range e.kinds {
		if k.Represents(err) {
			return true
		}
	}
	return false
}

func (e *multiKind) String() string {
	var str string
	for _, k := range e.kinds {
		str += k.String() + ","
	}
	return strings.TrimSuffix(str, ",")
}

func (e *multiKind) Description() string {
	var str string
	for _, k := range e.kinds {
		str += k.Description() + "\n"
	}
	return strings.TrimSpace(str)
}

// CombineErrKinds combines multiple error kinds into a single error kind
// this is not recommended but available if needed
// It is currently used in ErrorX while printing the error
// It is recommended to implement a hierarchical error kind
// instead of using this outside of errkit
func CombineErrKinds(kind ...ErrKind) ErrKind {
	// while combining it also consolidates child error kinds into parent
	// but note it currently does not support deeply nested childs
	// and can only consolidate immediate childs
	f := &multiKind{}
	uniq := map[ErrKind]struct{}{}
	for _, k := range kind {
		if k == nil || k.String() == "" {
			continue
		}
		if val, ok := k.(*multiKind); ok {
			for _, v := range val.kinds {
				uniq[v] = struct{}{}
			}
		} else {
			uniq[k] = struct{}{}
		}
	}
	all := maps.Keys(uniq)
	for _, k := range all {
		for u := range uniq {
			if k.IsParent(u) {
				delete(uniq, u)
			}
		}
	}
	if len(uniq) > 1 {
		// check and remove unknown error kind
		for k := range uniq {
			if k.Is(ErrKindUnknown) {
				delete(uniq, k)
			}
		}
	}

	f.kinds = maps.Keys(uniq)
	if len(f.kinds) > MaxErrorDepth {
		f.kinds = f.kinds[:MaxErrorDepth]
	}
	if len(f.kinds) == 1 {
		return f.kinds[0]
	}
	return f
}

// GetErrorKind returns the first error kind from the error
// extra error kinds can be passed as optional arguments
func GetErrorKind(err error, defs ...ErrKind) ErrKind {
	x := &ErrorX{}
	parseError(x, err)
	if x.kind != nil {
		if val, ok := x.kind.(*multiKind); ok && len(val.kinds) > 0 {
			// if multi kind return first kind
			return val.kinds[0]
		}
		return x.kind
	}
	// if no kind is found return default error kind
	// parse if defs are given
	for _, def := range defs {
		if def.Represents(x) {
			return def
		}
	}
	// check in default error kinds
	for _, def := range DefaultErrorKinds {
		if def.Represents(x) {
			return def
		}
	}
	return ErrKindUnknown
}

// GetAllErrorKinds returns all error kinds from the error
// this should not be used unless very good reason to do so
func GetAllErrorKinds(err error, defs ...ErrKind) []ErrKind {
	kinds := []ErrKind{}
	x := &ErrorX{}
	parseError(x, err)
	if x.kind != nil {
		if val, ok := x.kind.(*multiKind); ok {
			kinds = append(kinds, val.kinds...)
		} else {
			kinds = append(kinds, x.kind)
		}
	}
	for _, def := range defs {
		if def.Represents(x) {
			kinds = append(kinds, def)
		}
	}
	if len(kinds) == 0 {
		kinds = append(kinds, ErrKindUnknown)
	}
	return kinds
}
