package jenkins

import "testing"

func TestDoCheck(t *testing.T) {
	t.Run("CVE_2016_0792", func(t *testing.T) {
		if got := DoCheck("http://127.0.0.1:8080"); !got {
			t.Errorf("DoCheck() = %v, want %v", got, true)
		}
	})
}
