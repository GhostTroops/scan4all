package util

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func TestDelayClearCallbackRunsOnce(t *testing.T) {
	key := fmt.Sprintf("delay-clear-test-%p", t)
	defer delayClear.Delete(key)

	var calls atomic.Int32
	RegDelayCbk(key, func() {
		calls.Add(1)
	}, nil, 0, 0)

	var wg sync.WaitGroup
	DoDelayClear(&wg)
	DoNow(key)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("callback called %d times, want 1", got)
	}
}

func TestDelayClearHonorsDelay(t *testing.T) {
	key := fmt.Sprintf("delay-clear-delay-test-%p", t)
	defer delayClear.Delete(key)

	var calls atomic.Int32
	RegDelayCbk(key, func() {
		calls.Add(1)
	}, nil, 0, 60)

	var wg sync.WaitGroup
	DoDelayClear(&wg)
	wg.Wait()

	if got := calls.Load(); got != 0 {
		t.Fatalf("callback called %d times before delay elapsed, want 0", got)
	}
}

func TestDelayClearUpTimeIsSafeDuringClear(t *testing.T) {
	key := fmt.Sprintf("delay-clear-uptime-test-%p", t)
	defer delayClear.Delete(key)

	RegDelayCbk(key, func() {}, nil, 0, 60)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			UpTime(key)
		}
	}()
	DoDelayClear(&wg)
	wg.Wait()
}
