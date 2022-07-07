package fileutil

import (
	"errors"
	"io"
	"time"
)

var TimeoutError = errors.New("Timeout")

// TimeoutReader is a reader wrapper that stops waiting after Timeout
type TimeoutReader struct {
	Timeout     time.Duration
	Reader      io.Reader
	timeoutchan chan struct{}
	datachan    chan struct{}
}

// Read into the buffer
func (reader TimeoutReader) Read(p []byte) (n int, err error) {
	if reader.datachan == nil {
		reader.datachan = make(chan struct{})
	}
	if reader.timeoutchan == nil {
		reader.timeoutchan = make(chan struct{})
	}
	go func() {
		// if timeout is zero behaves like a normal reader
		if reader.Timeout > 0 {
			time.Sleep(reader.Timeout)
			reader.timeoutchan <- struct{}{}
		}
	}()
	go func() {
		n, err = reader.Reader.Read(p)
		reader.datachan <- struct{}{}
	}()

	select {
	case <-reader.timeoutchan:
		err = TimeoutError
		return
	case <-reader.datachan:
		return
	}
}
