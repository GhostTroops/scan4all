//go:build linux

package updateutils

import (
	"github.com/zcalusic/sysinfo"
)

// Get OS Vendor returns the linux distribution vendor
// if not linux then returns runtime.GOOS
func GetOSVendor() string {
	var si sysinfo.SysInfo
	si.GetSysInfo()
	return si.OS.Vendor
}
