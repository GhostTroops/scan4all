//go:build darwin || linux

package rawmode

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

func init() {
	GetMode = func(std *os.File) (interface{}, error) {
		return getMode(std)
	}

	SetMode = func(std *os.File, mode interface{}) error {
		m, ok := mode.(*syscall.Termios)
		if !ok {
			return errors.New("invalid syscall.Termios")
		}
		return setMode(std, m)
	}

	SetRawMode = func(std *os.File, mode interface{}) error {
		m, ok := mode.(*syscall.Termios)
		if !ok {
			return errors.New("invalid syscall.Termios")
		}
		return setRawMode(std, m)
	}

	Read = func(std *os.File, buf []byte) (int, error) {
		return read(std, buf)
	}
}

func getTermios(fd uintptr) (*syscall.Termios, error) {
	var t syscall.Termios
	_, _, err := syscall.Syscall6(
		syscall.SYS_IOCTL,
		os.Stdin.Fd(),
		TCGETS,
		uintptr(unsafe.Pointer(&t)),
		0, 0, 0)

	return &t, err
}

func setTermios(fd uintptr, term *syscall.Termios) error {
	_, _, err := syscall.Syscall6(
		syscall.SYS_IOCTL,
		os.Stdin.Fd(),
		TCSETS,
		uintptr(unsafe.Pointer(term)),
		0, 0, 0)
	return err
}

func setRaw(term *syscall.Termios) {
	// This attempts to replicate the behaviour documented for cfmakeraw in
	// the termios(3) manpage.
	term.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	term.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	term.Cflag &^= syscall.CSIZE | syscall.PARENB
	term.Cflag |= syscall.CS8

	term.Cc[syscall.VMIN] = 1
	term.Cc[syscall.VTIME] = 0
}

func getMode(std *os.File) (*syscall.Termios, error) {
	return getTermios(os.Stdin.Fd())
}

func setMode(std *os.File, mode *syscall.Termios) error {
	return setTermios(os.Stdin.Fd(), mode)
}

func setRawMode(std *os.File, mode *syscall.Termios) error {
	setRaw(mode)
	return SetMode(std, mode)
}

func read(std *os.File, buf []byte) (int, error) {
	return syscall.Read(int(os.Stdin.Fd()), buf)
}
