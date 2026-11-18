//go:build windows

package process

import (
	"os"
	"syscall"
)

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procGenerateConsoleCtrlEvent = kernel32.NewProc("GenerateConsoleCtrlEvent")
)

// SendInterrupt sends an interrupt signal to the current process.
// On Windows, this uses GenerateConsoleCtrlEvent with CTRL_BREAK_EVENT
// because Go's p.Signal(os.Interrupt) is not implemented on Windows.
func SendInterrupt() {
	// Send CTRL_BREAK_EVENT to current process's process group
	// Using os.Getpid() targets only processes in our group (typically just us in production)
	// This avoids sending to all console processes (group 0) which would kill parent processes
	pid := os.Getpid()
	procGenerateConsoleCtrlEvent.Call(syscall.CTRL_BREAK_EVENT, uintptr(pid))
}
