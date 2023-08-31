package reader

import (
	"io"
	"math"
	"time"
)

// FrozenReader is a reader that never returns
type FrozenReader struct{}

// Read into the buffer
func (reader FrozenReader) Read(p []byte) (n int, err error) {
	time.Sleep(math.MaxInt32 * time.Second)
	return 0, io.EOF
}
