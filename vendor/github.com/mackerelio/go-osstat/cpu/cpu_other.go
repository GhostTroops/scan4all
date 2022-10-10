//go:build !linux && !darwin
// +build !linux,!darwin

package cpu

import (
	"fmt"
	"runtime"
)

// Get cpu statistics
func Get() (*Stats, error) {
	return nil, fmt.Errorf("cpu statistics not implemented for: %s", runtime.GOOS)
}

// Stats represents cpu statistics
type Stats struct {
	User, System, Idle, Nice, Total uint64
}
