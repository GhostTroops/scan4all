//go:build windows

package rawmode

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

var (
	// load kernel32 lib
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	// get handlers to console API
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

const (
	enableLineInput       = 2
	enableEchoInput       = 4
	enableProcessedInput  = 1
	enableWindowInput     = 8   //nolint
	enableMouseInput      = 16  //nolint
	enableInsertMode      = 32  //nolint
	enableQuickEditMode   = 64  //nolint
	enableExtendedFlags   = 128 //nolint
	enableAutoPosition    = 256 //nolint
	enableProcessedOutput = 1   //nolint
	enableWrapAtEolOutput = 2   //nolint
)

func init() {
	GetMode = func(std *os.File) (interface{}, error) {
		return getMode(std)
	}

	SetMode = func(std *os.File, mode interface{}) error {
		m, ok := mode.(uint32)
		if !ok {
			return errors.New("invalid syscall.Termios")
		}
		return setMode(std, m)
	}

	SetRawMode = func(std *os.File, mode interface{}) error {
		m, ok := mode.(uint32)
		if !ok {
			return errors.New("invalid syscall.Termios")
		}
		return setRawMode(std, m)
	}

	Read = func(std *os.File, buf []byte) (int, error) {
		return read(std, buf)
	}
}

func getTermMode(fd uintptr) (uint32, error) {
	var mode uint32
	_, _, err := syscall.SyscallN(
		procGetConsoleMode.Addr(),
		fd,
		uintptr(unsafe.Pointer(&mode)),
		0)
	if err != 0 {
		return mode, err
	}
	return mode, nil
}

func setTermMode(fd uintptr, mode uint32) error {
	_, _, err := syscall.SyscallN(
		procSetConsoleMode.Addr(),
		fd,
		uintptr(mode),
		0)
	if err != 0 {
		return err
	}
	return nil
}

// GetMode from file descriptor
func getMode(std *os.File) (uint32, error) {
	return getTermMode(os.Stdin.Fd())
}

// SetMode to file descriptor
func setMode(std *os.File, mode uint32) error {
	return setTermMode(os.Stdin.Fd(), mode)
}

// SetRawMode to file descriptor enriching existign mode with raw console flags
func setRawMode(std *os.File, mode uint32) error {
	mode &^= (enableEchoInput | enableProcessedInput | enableLineInput | enableProcessedOutput)
	return SetMode(std, mode)
}

// Read from file descriptor to buffer
func read(std *os.File, buf []byte) (int, error) {
	return syscall.Read(syscall.Handle(os.Stdin.Fd()), buf)
}
