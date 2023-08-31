package reader

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/projectdiscovery/utils/reader/rawmode"
)

type KeyPressReader struct {
	originalMode interface{}
	Timeout      time.Duration
	datachan     chan []byte
	Once         *sync.Once
	Raw          bool
	BufferSize   int
}

func (reader *KeyPressReader) Start() error {
	reader.Once.Do(func() {
		go reader.read()
		reader.originalMode, _ = rawmode.GetMode(os.Stdin)
		if reader.Raw {
			reader.BufferSize = 1
		} else {
			reader.BufferSize = 512
		}
	})
	// set raw mode
	if reader.Raw {
		mode, _ := rawmode.GetMode(os.Stdin)
		return rawmode.SetRawMode(os.Stdin, mode)
	}

	// proceed with buffered input - only new lines are detected
	return nil
}

func (reader *KeyPressReader) Stop() error {
	// disable raw mode
	if reader.Raw {
		return rawmode.SetMode(os.Stdin, reader.originalMode)
	}

	// nop
	return nil
}

func (reader *KeyPressReader) read() {
	if reader.datachan == nil {
		reader.datachan = make(chan []byte)
	}

	for {
		var (
			n   int
			err error
			r   = make([]byte, reader.BufferSize)
		)

		if reader.Raw {
			n, err = rawmode.Read(os.Stdin, r)
		} else {
			n, err = os.Stdin.Read(r)
		}
		if n > 0 && err == nil {
			reader.datachan <- r
		}
	}
}

// Read into the buffer
func (reader KeyPressReader) Read(p []byte) (n int, err error) {
	var (
		ctx    context.Context
		cancel context.CancelFunc
	)
	if reader.Timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(reader.Timeout))
		defer cancel()
	}

	select {
	case <-ctx.Done():
		err = ErrTimeout
		return
	case data := <-reader.datachan:
		n = copy(p, data)
		return
	}
}
