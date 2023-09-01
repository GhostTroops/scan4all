package fdmax

import "errors"

var (
	// ErrUnsupportedPlatform error if the platform doesn't support file descriptor increase via system api
	ErrUnsupportedPlatform = errors.New("unsupported platform")
)

const (
	// UnixMax on unix systems
	UnixMax uint64 = 999999
	// OSXMax on darwin
	OSXMax uint64 = 24576
)

// Limits contains the file system descriptor limits
type Limits struct {
	Current uint64
	Max     uint64
}
