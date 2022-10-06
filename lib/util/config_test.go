package util

import (
	"fmt"
	"sync"
	"testing"
)

func TestTestIs404(t *testing.T) {
	Init2()
	var Wg = sync.WaitGroup{}
	// 单独测试没有问题
	for i := 8070; i < 8082; i++ {
		Wg.Add(1)
		go func(n int) {
			defer Wg.Done()
			s1 := fmt.Sprintf("https://127.0.0.1:%d/scan4all", n)
			if resp, err, ok := TestIs404(s1); ok && nil == err {
				t.Log(resp.StatusCode, s1)
			} else {
				if n == 8081 && nil != err {
					t.Error(s1, err)
				}
			}
		}(i)

	}
	Wg.Wait()
}
