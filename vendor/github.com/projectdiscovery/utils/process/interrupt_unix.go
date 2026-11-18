//go:build !windows

package process

import "os"

// SendInterrupt sends an interrupt signal to the current process.
// On Unix systems, this sends os.Interrupt (SIGINT).
func SendInterrupt() {
	if p, err := os.FindProcess(os.Getpid()); err == nil {
		_ = p.Signal(os.Interrupt)
	}
}
