package cache

import (
	"time"
)

type janitor struct {
	Interval time.Duration
	stop     chan struct{}
}

func (j *janitor) Run(c *cacheMemory) {
	ticker := time.NewTicker(j.Interval)
	for {
		select {
		case <-ticker.C:
			c.DeleteExpired()
		case <-j.stop:
			ticker.Stop()
			return
		}
	}
}

func stopJanitor(c *cacheMemory) {
	c.janitor.stop <- struct{}{}
}

func runJanitor(c *cacheMemory, ci time.Duration) {
	j := &janitor{
		Interval: ci,
		stop:     make(chan struct{}),
	}
	c.janitor = j
	go j.Run(c)
}
