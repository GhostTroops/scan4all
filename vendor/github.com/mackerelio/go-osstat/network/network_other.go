//go:build !linux && !darwin && !freebsd && !netbsd
// +build !linux,!darwin,!freebsd,!netbsd

package network

import (
	"fmt"
	"runtime"
)

// Get network statistics
func Get() ([]Stats, error) {
	return nil, fmt.Errorf("network statistics not implemented for: %s", runtime.GOOS)
}

// Stats represents network statistics
type Stats struct {
	Name             string
	RxBytes, TxBytes uint64
}
