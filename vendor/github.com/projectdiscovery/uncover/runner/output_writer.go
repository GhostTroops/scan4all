package runner

import (
	"crypto/sha1"
	"io"
	"sync"

	lru "github.com/hashicorp/golang-lru"
)

type OutputWriter struct {
	cache   *lru.Cache
	writers []io.Writer
	sync.RWMutex
}

func NewOutputWriter() (*OutputWriter, error) {
	lastPrintedCache, err := lru.New(2048)
	if err != nil {
		return nil, err
	}
	return &OutputWriter{cache: lastPrintedCache}, nil
}

func (o *OutputWriter) AddWriters(writers ...io.Writer) {
	o.writers = append(o.writers, writers...)
}

func (o *OutputWriter) Write(data []byte) {
	o.Lock()
	defer o.Unlock()

	// skip duplicates in the last 2048 printed items
	itemHash := sha1.Sum(data)
	if o.cache.Contains(itemHash) {
		return
	}
	o.cache.Add(itemHash, struct{}{})

	for _, writer := range o.writers {
		_, _ = writer.Write(data)
		_, _ = writer.Write([]byte("\n"))
	}
}

func (o *OutputWriter) WriteString(data string) {
	o.Write([]byte(data))
}
