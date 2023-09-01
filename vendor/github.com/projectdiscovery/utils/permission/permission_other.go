//go:build darwin || freebsd || netbsd || openbsd || solaris || android || ios || (linux && armv7l)

package permissionutil

import (
	"os"
)

// checkCurrentUserRoot checks if the current user is root
func checkCurrentUserRoot() (bool, error) {
	return os.Geteuid() == 0, nil
}

// checkCurrentUserCapNetRaw checks if the current user has the CAP_NET_RAW capability
func checkCurrentUserCapNetRaw() (bool, error) {
	return false, ErrNotImplemented
}
