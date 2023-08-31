//go:build darwin

package rawmode

import "syscall"

func init() {
	TCSETS = syscall.TIOCGETA
	TCGETS = syscall.TIOCSETA
}
