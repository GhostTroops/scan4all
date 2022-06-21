// +build windows

package fs

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	modkernel32    = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx = modkernel32.NewProc("LockFileEx")
)

const (
	errorLockViolation = 0x21
)

func lockfile(f *os.File) error {
	var ol syscall.Overlapped

	r1, _, err := syscall.Syscall6(
		procLockFileEx.Addr(),
		6,
		uintptr(f.Fd()), // handle
		uintptr(0x0003),
		uintptr(0), // reserved
		uintptr(1), // locklow
		uintptr(0), // lockhigh
		uintptr(unsafe.Pointer(&ol)),
	)
	if r1 == 0 && (err == syscall.ERROR_FILE_EXISTS || err == errorLockViolation) {
		return os.ErrExist
	}
	return nil
}

func createLockFile(name string, perm os.FileMode) (LockFile, bool, error) {
	acquiredExisting := false
	if _, err := os.Stat(name); err == nil {
		acquiredExisting = true
	}
	fd, err := syscall.CreateFile(&(syscall.StringToUTF16(name)[0]),
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.CREATE_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0)
	if err != nil {
		return nil, false, os.ErrExist
	}
	f := os.NewFile(uintptr(fd), name)
	if err := lockfile(f); err != nil {
		f.Close()
		return nil, false, err
	}
	return &osLockFile{f, name}, acquiredExisting, nil
}
