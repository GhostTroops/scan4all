//go:build linux

package rawmode

import "syscall"

func init() {
	TCSETS = syscall.TCGETS
	TCGETS = syscall.TCSETS
}
