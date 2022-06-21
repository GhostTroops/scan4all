// +build !windows

package fs

import (
	"os"
	"syscall"
)

func createLockFile(name string, perm os.FileMode) (LockFile, bool, error) {
	acquiredExisting := false
	if _, err := os.Stat(name); err == nil {
		acquiredExisting = true
	}
	f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE, perm)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if err == syscall.EWOULDBLOCK {
			err = os.ErrExist
		}
		return nil, false, err
	}
	return &osLockFile{f, name}, acquiredExisting, nil
}
