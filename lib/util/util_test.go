package util

import (
	"fmt"
	"os"
	"sync"
	"testing"
)

func TestHttpRequset(t *testing.T) {
	// 集成/压测型用例：会对本机 3~8082 端口发起 8000 个并发请求，默认跳过
	if "" == os.Getenv("SCAN4ALL_TEST_LOCAL_SCAN") {
		t.Skip("本机端口压测用例，设置 SCAN4ALL_TEST_LOCAL_SCAN=1 后再运行")
	}
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
