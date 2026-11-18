package sources

import "context"

type Query struct {
	Query string
	Limit int
}

// Agent fans out a query to one upstream search engine and streams results
// on the returned channel. Implementations must honor ctx during channel
// sends so cancellation does not leak the producer goroutine.
type Agent interface {
	Query(ctx context.Context, session *Session, query *Query) (chan Result, error)
	Name() string
}

// SendResult delivers r on ch unless ctx is cancelled first. It returns
// false when the caller should stop producing, freeing producer goroutines
// blocked on send when no reader remains downstream.
func SendResult(ctx context.Context, ch chan<- Result, r Result) bool {
	select {
	case <-ctx.Done():
		return false
	case ch <- r:
		return true
	}
}
