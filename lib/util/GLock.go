package util

import (
	"fmt"
	"sync"
	"time"
)

var lk sync.Mutex

// 全局统一锁，避免相同目标、相同任务重复执行
// 库级：不重复
// 执行第一次，就进行标记，第二次返回true
func IsDoIt(s string, nType int) bool {
	lk.Lock()
	defer lk.Unlock()
	k := fmt.Sprintf("IsDo%s_%d", s, nType)
	if o := clientHttpCc.Get(k); nil != o {
		if v, ok := o.Value().(bool); ok && v {
			return v
		}
	}
	clientHttpCc.Set(k, true, time.Hour*24)
	return false
}
