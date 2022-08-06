package x

import (
	"net"
)

// Dialer is a common interface for dialing
type Dialer interface {
	Dial(network, addr string) (net.Conn, error)
	DialTCP(network string, laddr, raddr *net.TCPAddr) (*net.TCPConn, error)
	DialUDP(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error)
}

type Dial struct {
}

// DefaultDial is the default dialer in net package
var DefaultDial = &Dial{}

func (d *Dial) Dial(network, addr string) (net.Conn, error) {
	return net.Dial(network, addr)
}

func (d *Dial) DialTCP(network string, laddr, raddr *net.TCPAddr) (*net.TCPConn, error) {
	return net.DialTCP(network, laddr, raddr)
}

func (d *Dial) DialUDP(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	return net.DialUDP(network, laddr, raddr)
}
