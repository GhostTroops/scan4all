package bugbounty

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// 关闭端口上跑一遍，确认：1) 不会长时间阻塞；2) SetLogf 能接管全部输出；
// 3) 无漏洞时不产生 Finding。
func TestRunScan_ClosedPortNoFindings(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	SetLogf(func(format string, a ...interface{}) {
		mu.Lock()
		lines = append(lines, format)
		mu.Unlock()
	})
	defer SetLogf(nil)

	done := make(chan []*Finding, 1)
	go func() {
		done <- RunScan([]string{"127.0.0.1:1"}, 2)
	}()

	select {
	case findings := <-done:
		if len(findings) != 0 {
			t.Errorf("closed port should yield no findings, got %d: %v", len(findings), findings)
		}
	case <-time.After(45 * time.Second):
		t.Fatal("RunScan did not return within 45s on a closed port")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(lines) == 0 {
		t.Log("no log lines captured (connection refused before fingerprint stage)")
		return
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "[FP") {
			t.Errorf("unexpected log line through SetLogf: %q", l)
		}
	}
}

func TestSetLogfNilRestoresDefault(t *testing.T) {
	called := false
	SetLogf(func(string, ...interface{}) { called = true })
	logf("x")
	if !called {
		t.Fatal("custom logf not used")
	}
	SetLogf(nil)
	if logf == nil {
		t.Fatal("logf should be restored, not nil")
	}
}
