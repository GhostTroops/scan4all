package cvescan

import (
	"bytes"
	"testing"
)

func TestTargetsFromBuffer(t *testing.T) {
	buf := bytes.NewBufferString(`http://10.0.0.1:8080/admin
https://10.0.0.2/login
10.0.0.3:22
http://10.0.0.1:8080/other
# comment line

https://10.0.0.4/`)
	got := TargetsFromBuffer(buf)
	want := []string{"10.0.0.1:8080", "10.0.0.2:443", "10.0.0.3:22", "10.0.0.4:443"}
	if len(got) != len(want) {
		t.Fatalf("targets count = %d (%v), want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("targets[%d] = %q, want %q (all: %v)", i, got[i], want[i], got)
		}
	}
}

func TestTargetsFromBuffer_Empty(t *testing.T) {
	if got := TargetsFromBuffer(nil); got != nil {
		t.Errorf("nil buffer should return nil, got %v", got)
	}
	if got := TargetsFromBuffer(bytes.NewBuffer(nil)); got != nil {
		t.Errorf("empty buffer should return nil, got %v", got)
	}
}
