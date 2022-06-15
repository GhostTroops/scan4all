package pogreb

import "expvar"

// Metrics holds the DB metrics.
type Metrics struct {
	Puts           expvar.Int
	Dels           expvar.Int
	Gets           expvar.Int
	HashCollisions expvar.Int
}
