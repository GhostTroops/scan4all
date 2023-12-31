package go_utils

import (
	"fmt"
	"github.com/go-ping/ping"
	"time"
)

func PingDns(s string, nCnt int, nTimeout time.Duration) float64 {
	pinger, err := ping.NewPinger(s)
	if err != nil {
		fmt.Printf("x")
		return 0
	}
	pinger.Timeout = nTimeout * time.Millisecond
	pinger.Count = nCnt
	err = pinger.Run() // Blocks until finished.
	if err != nil {
		fmt.Printf("x")
		return 0
	}
	fmt.Printf(".")
	stats := pinger.Statistics() // get s
	return stats.AvgRtt.Seconds()
}
