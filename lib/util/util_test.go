package util

import (
	"fmt"
	"sync"
	"testing"
)

func TestHttpRequset(t *testing.T) {
	var Wg = sync.WaitGroup{}
	// 单独测试没有问题
	for i := 33; i < 8082; i++ {
		Wg.Add(1)
		go func(n int) {
			defer Wg.Done()
			s1 := fmt.Sprintf("http://127.0.0.1:%d/scan4all", n)
			if resp, err := HttpRequset(s1, "GET", "", false, nil); nil == err {
				t.Log(resp.StatusCode, s1)
			} else {
				if n == 8081 {
					t.Error(s1, err)
				}
			}
		}(i)

	}
	Wg.Wait()
}
