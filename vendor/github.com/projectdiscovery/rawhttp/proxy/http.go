package proxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/rawhttp/client"
)

func httpDialer(proxyAddr string, timeout time.Duration, fd *fastdialer.Dialer) DialFunc {
	return func(addr string) (net.Conn, error) {
		var netConn net.Conn
		var err error
		var auth string
		// close the connection when an error occurs
		defer func() {
			if err != nil && netConn != nil {
				_ = netConn.Close()
			}
		}()
		u, err := url.Parse(proxyAddr)
		if err != nil {
			return nil, err
		}
		if strings.Contains(proxyAddr, "@") {
			split := strings.Split(proxyAddr, "@")
			auth = base64.StdEncoding.EncodeToString([]byte(split[0]))
			proxyAddr = split[1]
		}
		if fd != nil {
			netConn, err = fd.Dial(context.TODO(), "tcp", u.Host)
		} else {
			netConn, err = net.DialTimeout("tcp", u.Host, timeout)
		}

		if err != nil {
			return nil, err
		}
		conn := client.NewClient(netConn)

		req := "CONNECT " + addr + " HTTP/1.1\r\n"
		if auth != "" {
			req += "Proxy-Authorization: Basic " + auth + "\r\n"
		}
		req += "\r\n"
		clientReq := &client.Request{
			RawBytes: []byte(req),
		}
		if err = conn.WriteRequest(clientReq); err != nil {
			return nil, err
		}
		resp, err := conn.ReadResponse(false)
		if err != nil {
			return nil, err
		}
		if resp.Status.Code != 200 {
			return nil, fmt.Errorf("could not connect to proxy: %s status code: %d", proxyAddr, resp.Status.Code)
		}

		return netConn, nil
	}
}

func HTTPDialer(proxyAddr string, timeout time.Duration) DialFunc {
	return httpDialer(proxyAddr, timeout, nil)
}

func HTTPFastDialer(proxyAddr string, timeout time.Duration, fd *fastdialer.Dialer) DialFunc {
	return httpDialer(proxyAddr, timeout, fd)
}
