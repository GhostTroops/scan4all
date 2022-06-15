package retryablehttp

import (
	"math"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

// Backoff specifies a policy for how long to wait between retries.
// It is called after a failing request to determine the amount of time
// that should pass before trying again.
type Backoff func(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration

// DefaultBackoff provides a default callback for Client.Backoff which
// will perform exponential backoff based on the attempt number and limited
// by the provided minimum and maximum durations.
func DefaultBackoff() func(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration {
	return func(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration {
		mult := math.Pow(2, float64(attemptNum)) * float64(min)

		sleep := time.Duration(mult)
		if float64(sleep) != mult || sleep > max {
			sleep = max
		}
		return sleep
	}
}

// LinearJitterBackoff provides a callback for Client.Backoff which will
// perform linear backoff based on the attempt number and with jitter to
// prevent a thundering herd.
//
// min and max here are *not* absolute values. The number to be multipled by
// the attempt number will be chosen at random from between them, thus they are
// bounding the jitter.
//
// For instance:
// - To get strictly linear backoff of one second increasing each retry, set
// both to one second (1s, 2s, 3s, 4s, ...)
// - To get a small amount of jitter centered around one second increasing each
// retry, set to around one second, such as a min of 800ms and max of 1200ms
// (892ms, 2102ms, 2945ms, 4312ms, ...)
// - To get extreme jitter, set to a very wide spread, such as a min of 100ms
// and a max of 20s (15382ms, 292ms, 51321ms, 35234ms, ...)
func LinearJitterBackoff() func(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration {
	// Seed a global random number generator and use it to generate random
	// numbers for the backoff. Use a mutex for protecting the source
	rand := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
	randMutex := &sync.Mutex{}

	return func(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration {
		// attemptNum always starts at zero but we want to start at 1 for multiplication
		attemptNum++

		if max <= min {
			// Unclear what to do here, or they are the same, so return min *
			// attemptNum
			return min * time.Duration(attemptNum)
		}

		// Pick a random number that lies somewhere between the min and max and
		// multiply by the attemptNum. attemptNum starts at zero so we always
		// increment here. We first get a random percentage, then apply that to the
		// difference between min and max, and add to min.
		randMutex.Lock()
		jitter := rand.Float64() * float64(max-min)
		randMutex.Unlock()

		jitterMin := int64(jitter) + int64(min)
		return time.Duration(jitterMin * int64(attemptNum))
	}
}

// FullJitterBackoff implements capped exponential backoff
// with jitter. Algorithm is fast because it does not use floating
// point arithmetics. It returns a random number between [0...n]
// https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
func FullJitterBackoff() func(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration {
	// Seed a global random number generator and use it to generate random
	// numbers for the backoff. Use a mutex for protecting the source
	rand := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
	randMutex := &sync.Mutex{}

	return func(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration {
		duration := attemptNum * 1000000000 << 1

		randMutex.Lock()
		jitter := rand.Intn(duration-attemptNum) + int(min)
		randMutex.Unlock()

		if jitter > int(max) {
			return max
		}

		return time.Duration(jitter)
	}
}

// ExponentialJitterBackoff provides a callback for Client.Backoff which will
// perform en exponential backoff based on the attempt number and with jitter to
// prevent a thundering herd.
//
// min and max here are *not* absolute values. The number to be multipled by
// the attempt number will be chosen at random from between them, thus they are
// bounding the jitter.
func ExponentialJitterBackoff() func(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration {
	// Seed a global random number generator and use it to generate random
	// numbers for the backoff. Use a mutex for protecting the source
	rand := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
	randMutex := &sync.Mutex{}

	return func(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration {
		minf := float64(min)
		mult := math.Pow(2, float64(attemptNum)) * minf

		randMutex.Lock()
		jitter := rand.Float64() * (mult - minf)
		randMutex.Unlock()

		mult = mult + jitter

		sleep := time.Duration(mult)
		if sleep > max {
			sleep = max
		}

		return sleep
	}
}
