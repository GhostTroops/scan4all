// +build linux darwin

package clistats

import "syscall"

func kill() {
	syscall.Kill(syscall.Getpid(), syscall.SIGINT)
}
