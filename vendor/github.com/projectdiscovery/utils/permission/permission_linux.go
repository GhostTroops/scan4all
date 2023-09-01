//go:build linux

package permissionutil

import (
	"errors"
	"os"
	"runtime"

	raceutil "github.com/projectdiscovery/utils/race"

	"golang.org/x/sys/unix"
)

// checkCurrentUserRoot checks if the current user is root
func checkCurrentUserRoot() (bool, error) {
	return os.Geteuid() == 0, nil
}

// checkCurrentUserCapNetRaw checks if the current user has the CAP_NET_RAW capability
func checkCurrentUserCapNetRaw() (bool, error) {
	if raceutil.Enabled {
		return false, errors.New("race detector enabled")
	}
	// runtime.LockOSThread interferes with race detection
	header := unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
		Pid:     int32(os.Getpid()),
	}
	data := unix.CapUserData{}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	err := unix.Capget(&header, &data)
	if err != nil {
		return false, err
	}
	data.Inheritable = (1 << unix.CAP_NET_RAW)
	if err = unix.Capset(&header, &data); err != nil {
		return false, err
	}
	return true, nil
}
