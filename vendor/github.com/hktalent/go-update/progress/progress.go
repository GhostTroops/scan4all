// Package progress provides a proxy for download progress.
package progress

import (
	"io"
	"time"

	pb "github.com/gosuri/uiprogress"
)

// TODO: refactor to just check EOF

// reader wrapping a progress bar.
type reader struct {
	bars    *pb.Progress
	r       io.ReadCloser
	written int
}

// Read implementation.
func (r *reader) Read(b []byte) (int, error) {
	n, err := r.r.Read(b)
	r.written += n
	r.bars.Bars[0].Set(r.written)
	return n, err
}

// Close implementation.
func (r *reader) Close() error {
	r.bars.Stop()
	return r.r.Close()
}

// Reader returns a progress bar reader.
func Reader(size int, r io.ReadCloser) io.ReadCloser {
	bars := pb.New()
	bars.Width = 50
	bars.AddBar(size)
	bars.Start()
	bars.SetRefreshInterval(50 * time.Millisecond)
	bars.Bars[0].AppendCompleted()

	return &reader{
		bars: bars,
		r:    r,
	}
}
