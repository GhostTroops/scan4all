package connpool

import (
	"context"
	"net"

	"github.com/projectdiscovery/fastdialer/fastdialer"
)

// OneTimePool is a pool designed to create continous bare connections that are for one time only usage
type OneTimePool struct {
	address         string
	idleConnections chan net.Conn
	InFlightConns   *InFlightConns
	ctx             context.Context
	cancel          context.CancelFunc
	FastDialer      *fastdialer.Dialer
}

func NewOneTimePool(ctx context.Context, address string, poolSize int) (*OneTimePool, error) {
	idleConnections := make(chan net.Conn, poolSize)
	inFlightConns, err := NewInFlightConns()
	if err != nil {
		return nil, err
	}
	pool := &OneTimePool{
		address:         address,
		idleConnections: idleConnections,
		InFlightConns:   inFlightConns,
	}
	if ctx != nil {
		pool.ctx = ctx
	}
	pool.ctx, pool.cancel = context.WithCancel(ctx)
	return pool, nil
}

// Acquire acquires an idle connection from the pool
func (p *OneTimePool) Acquire(c context.Context) (net.Conn, error) {
	select {
	case <-p.ctx.Done():
		return nil, p.ctx.Err()
	case <-c.Done():
		return nil, c.Err()
	case conn := <-p.idleConnections:
		p.InFlightConns.Remove(conn)
		return conn, nil
	}
}

func (p *OneTimePool) Run() error {
	for {
		select {
		case <-p.ctx.Done():
			return p.ctx.Err()
		default:
			var (
				conn net.Conn
				err  error
			)
			if p.FastDialer != nil {
				conn, err = p.FastDialer.Dial(p.ctx, "tcp", p.address)
			} else {
				conn, err = net.Dial("tcp", p.address)
			}
			if err == nil {
				p.InFlightConns.Add(conn)
				p.idleConnections <- conn
			}
		}
	}
}

func (p *OneTimePool) Close() error {
	p.cancel()
	return p.InFlightConns.Close()
}
