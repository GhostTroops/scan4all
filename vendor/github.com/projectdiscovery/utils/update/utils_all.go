//go:build !linux

package updateutils

import (
	"runtime"
)

// Get OS Vendor returns the linux distribution vendor
// if not linux then returns runtime.GOOS
func GetOSVendor() string {
	return runtime.GOOS
}
