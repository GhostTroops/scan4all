package runner

import (
	"context"
	"github.com/boy-hack/ksubdomain/runner/statusdb"
	"sync/atomic"
	"time"
)

func (r *runner) retry(ctx context.Context) {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// 循环检测超时的队列
			now := time.Now()
			r.hm.Scan(func(key string, v statusdb.Item) error {
				if r.maxRetry > 0 && v.Retry > r.maxRetry {
					r.hm.Del(key)
					atomic.AddUint64(&r.faildIndex, 1)
					return nil
				}
				if int64(now.Sub(v.Time)) >= r.timeout {
					// 重新发送
					r.sender <- key
				}
				return nil
			})
		}
	}
}
