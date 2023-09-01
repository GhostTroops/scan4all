package proxy

import (
	"net"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

func Socks5Dialer(proxyAddr string, timeout time.Duration) DialFunc {
	var (
		u      *url.URL
		err    error
		dialer proxy.Dialer
	)
	if u, err = url.Parse(proxyAddr); err == nil {
		dialer, err = proxy.FromURL(u, proxy.Direct)
	}
	return func(addr string) (net.Conn, error) {
		if err != nil {
			return nil, err
		}
		return dialer.Dial("tcp", addr)
	}
}
