package go_utils

import (
	"context"
	"crypto/tls"
	"fmt"
	kcp "github.com/xtaci/kcp-go"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

/*
https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/json/proxies.json
https://raw.githubusercontent.com/mertguvencli/http-proxy-list/main/proxy-list/data-with-geolocation.json
https://www.freeproxy.world/?type=socks5&anonymity=4&country=&speed=&port=&page=1
https://www.proxy-list.download/SOCKS5
https://www.proxy-list.download/SOCKS5
https://list.proxylistplus.com/Socks-List-1
https://list.proxylistplus.com/Socks-List-2
http://proxydb.net/?protocol=https&protocol=socks5&anonlvl=2&anonlvl=4&country=
https://www.socks-proxy.net
*/
const TimeOut = 5 * time.Second

type CheckFunc func(szIp, szPort string, ctx context.Context, bOk chan bool, wg *sync.WaitGroup)

func GetConn(szIp, szPort string, ctx context.Context) (conn net.Conn, err error) {
	dialer := &net.Dialer{
		Timeout:   TimeOut,
		KeepAlive: 0,
		DualStack: true,
		Cancel:    ctx.Done(),
	}

	conn, err = dialer.DialContext(ctx, "tcp", net.JoinHostPort(szIp, szPort))

	return
}

// Check for KCP server
func CheckKcp(szIp, szPort string, ctx context.Context, bOk chan bool, wg *sync.WaitGroup) {
	defer wg.Done()
	conn, err := kcp.Dial(szIp + ":" + szPort)
	if err == nil {
		defer conn.Close()
		log.Println("found kcp")
		bOk <- true
	}
	bOk <- false
}
func CheckHttsProxy(szIp, szPort string, ctx context.Context, bOk chan bool, wg *sync.WaitGroup) {
	defer wg.Done()
	// 发送 CONNECT 请求并尝试建立 TLS 连接
	config := &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(&url.URL{
				Host: net.JoinHostPort(szIp, szPort),
			}),
			TLSClientConfig: config,
		},
		Timeout: TimeOut,
	}
	req, err := http.NewRequestWithContext(ctx, "CONNECT", "https://www.google.com", nil)
	if err != nil {
		fmt.Printf("HTTP request error: %s\n", err.Error())
		bOk <- false
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("HTTP response error: %s\n", err.Error())
		bOk <- false
		return
	}
	defer resp.Body.Close()

	// 检查响应状态码，如果是 200，则说明存在 HTTPS 代理服务
	if resp.StatusCode == 200 {
		bOk <- true
	}
	bOk <- false
}

// Check for HTTP proxy
func CheckHttProxy(szIp, szPort string, ctx context.Context, bOk chan bool, wg *sync.WaitGroup) {
	defer wg.Done()
	conn, err := GetConn(szIp, szPort, ctx)
	if err == nil {
		defer conn.Close()
		fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")
		buf := make([]byte, 100)
		_, err := conn.Read(buf)
		if err == nil {
			log.Println("found http proxy")
			bOk <- true
		}
	}
	bOk <- false
}

// Check for socks5 proxy
func CheckSocks5Proxy(szIp, szPort string, ctx context.Context, bOk chan bool, wg *sync.WaitGroup) {
	defer wg.Done()
	conn, err := GetConn(szIp, szPort, ctx)
	if err == nil {
		defer conn.Close()
		// Send SOCKS5 handshake request
		buf := []byte{0x05, 0x01, 0x00}
		_, err := conn.Write(buf)
		if err == nil {
			_, err := conn.Read(buf)
			if err == nil && buf[1] == 0 {
				log.Println("found socks5 proxy")
				bOk <- true
			}
		}
	}
	bOk <- false
}

// Check for sockss proxy
func CheckSocks4Proxy(szIp, szPort string, ctx context.Context, bOk chan bool, wg *sync.WaitGroup) {
	defer wg.Done()
	conn, err := GetConn(szIp, szPort, ctx)
	if err == nil {
		defer conn.Close()
		// Send SOCKS4 handshake request
		buf := make([]byte, 9)
		ip := net.ParseIP(szIp)
		buf[0] = 0x04          // Version
		buf[1] = 0x01          // Command (1 = establish a TCP/IP stream connection)
		buf[2] = byte(80 >> 8) // Destination port high byte
		buf[3] = byte(80)      // Destination port low byte
		buf[4] = ip[0]         // Destination IP address first octet
		buf[5] = ip[1]         // Destination IP address second octet
		buf[6] = ip[2]         // Destination IP address third octet
		buf[7] = ip[3]         // Destination IP address fourth octet
		buf[8] = 0x00          // Null terminator for user ID

		_, err := conn.Write(buf)
		if err == nil {
			buf := make([]byte, 8)
			_, err := conn.Read(buf)
			if err == nil && buf[1] == 0x5a {
				log.Println("found socks4 proxy")
				bOk <- true
			}
		}
	}
	bOk <- false
}

/*
detect http、socks5 proxy
*/
func DetectProxy(szIp, szPort string) bool {
	var wg sync.WaitGroup
	var bOk = make(chan bool, 1)
	var aX = []CheckFunc{CheckHttProxy, CheckHttsProxy, CheckSocks5Proxy, CheckSocks4Proxy} // , CheckKcp
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := len(aX)
	wg.Add(n)
	var bRst = false
	go func() {
		for {
			select {
			case bOk := <-bOk:
				n--
				if bOk {
					bRst = true
					cancel()
					return
				}
				if 0 >= n {
					cancel()
					return
				}
			}
		}
	}()
	for _, x := range aX {
		go x(szIp, szPort, ctx, bOk, &wg)
	}
	wg.Wait()
	return bRst
}
