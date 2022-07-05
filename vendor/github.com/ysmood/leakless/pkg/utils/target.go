package utils

import (
	"runtime"
	"strings"
)

// Target for build, a valid value is like "linux/amd64".
// To list all available targets run `go tool dist list`.
type Target string

// GetTarget via current runtime
func GetTarget() Target {
	return Target(runtime.GOOS + "/" + runtime.GOARCH)
}

// OS ...
func (t Target) OS() string {
	return strings.Split(string(t), "/")[0]
}

// ARCH ...
func (t Target) ARCH() string {
	return strings.Split(string(t), "/")[1]
}

// BinName for GOOS and GOARCH
func (t Target) BinName() string {
	return t.ARCH() + "_" + t.OS()
}
