package goob

import (
	"context"
	"sync"
)

// Observable hub
type Observable struct {
	ctx         context.Context
	lock        *sync.Mutex
	subscribers map[Events]func(Event)
}

// New observable instance
func New(ctx context.Context) *Observable {
	ob := &Observable{
		ctx:         ctx,
		lock:        &sync.Mutex{},
		subscribers: map[Events]func(Event){},
	}
	return ob
}

// Publish message to the queue
func (ob *Observable) Publish(e Event) {
	ob.lock.Lock()
	defer ob.lock.Unlock()

	for _, write := range ob.subscribers {
		write(e)
	}
}

// Subscribe message
func (ob *Observable) Subscribe(ctx context.Context) Events {
	ob.lock.Lock()
	defer ob.lock.Unlock()

	ctx, cancel := context.WithCancel(ctx)

	write, events := NewPipe(ctx)

	ob.subscribers[events] = write

	go func() {
		select {
		case <-ctx.Done():
		case <-ob.ctx.Done():
		}

		ob.lock.Lock()
		defer ob.lock.Unlock()

		delete(ob.subscribers, events)
		cancel()
	}()

	return events
}

// Len of the subscribers
func (ob *Observable) Len() int {
	ob.lock.Lock()
	defer ob.lock.Unlock()
	return len(ob.subscribers)
}
