package jarm

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	gojarm "github.com/hdm/jarm-go"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/tlsx/pkg/connpool"
)

const poolCount = 3

// fingerprint probes a single host/port
func HashWithDialer(dialer *fastdialer.Dialer, host string, port int, duration int) (string, error) {
	results := []string{}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	timeout := time.Duration(duration) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), (time.Duration(duration*poolCount) * time.Second))
	defer cancel()

	// using connection pool as we need multiple probes
	pool, err := connpool.NewOneTimePool(ctx, addr, poolCount)
	if err != nil {
		return "", err
	}
	pool.FastDialer = dialer

	defer pool.Close() //nolint
	go pool.Run()      //nolint

	for _, probe := range gojarm.GetProbes(host, port) {
		conn, err := pool.Acquire(ctx)
		if err != nil {
			continue
		}
		if conn == nil {
			continue
		}
		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		_, err = conn.Write(gojarm.BuildProbe(probe))
		if err != nil {
			results = append(results, "")
			_ = conn.Close()
			continue
		}
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		buff := make([]byte, 1484)
		_, _ = conn.Read(buff)
		_ = conn.Close()
		ans, err := gojarm.ParseServerHello(buff, probe)
		if err != nil {
			results = append(results, "")
			continue
		}
		results = append(results, ans)
	}
	hash := gojarm.RawHashToFuzzyHash(strings.Join(results, ","))
	return hash, nil
}
