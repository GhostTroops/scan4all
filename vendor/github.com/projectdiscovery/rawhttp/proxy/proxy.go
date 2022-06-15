package proxy

import (
	"net"
)

type DialFunc func(addr string) (net.Conn, error)
