package jenkins

import (
	"os"
	"testing"
)

func TestDoCheck(t *testing.T) {
	// 需要本地 Jenkins 靶场（127.0.0.1:8080），默认跳过
	if "" == os.Getenv("JENKINS_LAB") {
		t.Skip("设置 JENKINS_LAB=1 且本地 8080 有靶场时运行")
	}
	t.Run("CVE_2016_0792", func(t *testing.T) {
		if got := DoCheck("http://127.0.0.1:8080"); !got {
			t.Errorf("DoCheck() = %v, want %v", got, true)
		}
	})
}
