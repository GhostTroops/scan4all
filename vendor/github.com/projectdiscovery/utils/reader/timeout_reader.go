package reader

import (
	"context"
	"io"
	"time"
)

// TimeoutReader is a reader wrapper that stops waiting after Timeout
type TimeoutReader struct {
	Timeout  time.Duration
	Reader   io.Reader
	datachan chan struct{}
}

// Read into the buffer
func (reader TimeoutReader) Read(p []byte) (n int, err error) {
	var (
		ctx    context.Context
		cancel context.CancelFunc
	)
	if reader.Timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(reader.Timeout))
		defer cancel()
	}

	if reader.datachan == nil {
		reader.datachan = make(chan struct{})
	}

	go func() {
		n, err = reader.Reader.Read(p)
		reader.datachan <- struct{}{}
	}()

	select {
	case <-ctx.Done():
		err = ErrTimeout
		return
	case <-reader.datachan:
		return
	}
}
