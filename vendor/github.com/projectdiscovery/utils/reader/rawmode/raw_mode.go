package rawmode

import (
	"os"
)

var (
	// GetMode from file descriptor
	GetMode func(std *os.File) (interface{}, error)
	// SetMode to file descriptor
	SetMode func(std *os.File, mode interface{}) error
	// SetRawMode to file descriptor enriching existign mode with raw console flags
	SetRawMode func(std *os.File, mode interface{}) error
	// Read from file descriptor to buffer
	Read func(std *os.File, buf []byte) (int, error)

	TCSETS uintptr
	TCGETS uintptr
)
