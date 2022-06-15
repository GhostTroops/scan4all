package goob

import (
	"context"
	"sync"
)

// Event interface
type Event interface{}

// Events channel
type Events <-chan Event

// NewPipe instance.
// Pipe the Event via Write to Events. Events uses an internal buffer so it won't block Write.
func NewPipe(ctx context.Context) (Write func(Event), Events <-chan Event) {
	events := make(chan Event)
	lock := sync.Mutex{}
	buf := []Event{} // using slice is faster than linked-list in general cases
	wait := make(chan struct{}, 1)

	write := func(e Event) {
		lock.Lock()
		defer lock.Unlock()

		buf = append(buf, e)

		if len(wait) == 0 {
			select {
			case <-ctx.Done():
				return
			case wait <- struct{}{}:
			}
		}
	}

	go func() {
		defer close(events)

		for {
			lock.Lock()
			section := buf
			buf = []Event{}
			lock.Unlock()

			for _, e := range section {
				select {
				case <-ctx.Done():
					return
				case events <- e:
				}
			}

			select {
			case <-ctx.Done():
				return
			case <-wait:
			}
		}
	}()

	return write, events
}
