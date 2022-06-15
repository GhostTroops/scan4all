package clistats

import "time"

// tickerInterface is a time.Ticker interface implementation
type tickerInterface interface {
	Tick() <-chan time.Time
	Stop()
}

type ticker struct {
	t *time.Ticker
}

func (t *ticker) Tick() <-chan time.Time { return t.t.C }
func (t *ticker) Stop()                  { t.t.Stop() }

type noopTicker struct {
	tick chan time.Time
}

func (t *noopTicker) Tick() <-chan time.Time { return t.tick }
func (t *noopTicker) Stop()                  { close(t.tick) }
