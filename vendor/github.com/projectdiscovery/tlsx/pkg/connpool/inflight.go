package connpool

import (
	"net"
	"sync"

	"go.uber.org/multierr"
)

type InFlightConns struct {
	sync.RWMutex
	inflightConns map[net.Conn]struct{}
}

func NewInFlightConns() (*InFlightConns, error) {
	return &InFlightConns{inflightConns: make(map[net.Conn]struct{})}, nil
}

func (i *InFlightConns) Add(conn net.Conn) {
	i.Lock()
	defer i.Unlock()

	i.inflightConns[conn] = struct{}{}
}

func (i *InFlightConns) Remove(conn net.Conn) {
	i.Lock()
	defer i.Unlock()

	delete(i.inflightConns, conn)
}

func (i *InFlightConns) Close() error {
	i.Lock()
	defer i.Unlock()

	var errs []error

	for conn := range i.inflightConns {
		if err := conn.Close(); err != nil {
			errs = append(errs, err)
		}
		delete(i.inflightConns, conn)
	}

	return multierr.Combine(errs...)
}
