package util

import (
	"sync"
	"time"
)

// 延时自动初对象
type delayClearObj struct {
	mu          sync.Mutex
	GetCacheObj func() interface{} // 返回缓存对象
	FnCbk       func()             // 回调函数
	Time        int64              // 开始及时的时间
	DelayCall   int64              // 延时多少秒调用FnCbk
}

// cache 延时sec
//var nCacheTime = time.Second * 60

// 内存清理注册
var delayClear sync.Map

// 注册延时清理
//
//	n0 0表示60秒后执行
func RegDelayCbk(szKey string, fnCbk func(), cache func() interface{}, n0 int64, DelayCall int64) {
	delayClear.Store(szKey, &delayClearObj{
		Time:        time.Now().Unix() - n0,
		DelayCall:   DelayCall,
		FnCbk:       fnCbk,
		GetCacheObj: cache,
	})
}

// 重时间计数器
func UpTime(szKey string) {
	if o, ok := delayClear.Load(szKey); ok {
		x1 := o.(*delayClearObj)
		x1.mu.Lock()
		x1.Time = time.Now().Unix()
		x1.mu.Unlock()
	}
}

// 获取缓存对象
func GetCache(szKey string, bUpTime bool) interface{} {
	if o, ok := delayClear.Load(szKey); ok {
		x1 := o.(*delayClearObj)
		if bUpTime {
			UpTime(szKey)
		}
		return x1.GetCacheObj()
	}
	return nil
}

// 立刻执行
func DoNow(szKey string) {
	if o, ok := delayClear.Load(szKey); ok {
		x1 := o.(*delayClearObj)
		if delayClear.CompareAndDelete(szKey, x1) {
			x1.FnCbk()
		}
	}
}

// 单实例运行
var IsDo = make(chan struct{}, 1)

func DoSleep() {
	time.Sleep(4 * time.Second)
}

// 延时清理
func DoDelayClear(Wg1 ...*sync.WaitGroup) {
	var wg2 *sync.WaitGroup
	if 0 < len(Wg1) && nil != Wg1[0] {
		wg2 = Wg1[0]
	} else {
		wg2 = Wg
	}
	select {
	case IsDo <- struct{}{}:
	default:
		return
	}
	wg2.Add(1)
	go func() {
		defer func() {
			<-IsDo
			wg2.Done()
		}()
		nN := time.Now().Unix()
		delayClear.Range(func(key, value any) bool {
			if nil == value {
				delayClear.Delete(key)
				return true
			}
			x1 := value.(*delayClearObj)
			x1.mu.Lock()
			n09 := nN - x1.Time
			expired := n09 >= x1.DelayCall
			x1.mu.Unlock()
			//log.Printf("n09 = %d, now = %d, x1.Time = %d", n09, nN, x1.Time)
			if expired && delayClear.CompareAndDelete(key, x1) {
				x1.FnCbk()
				//log.Println("nuclei is closed : ", key)
			}
			return true
		})
	}()
	return
}
