package go_utils

import (
	"sync"
	"time"
)

// 延时自动初对象
type delayClearObj struct {
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
	delayClear.Store(szKey, &delayClearObj{Time: time.Now().Unix() - n0, FnCbk: fnCbk, GetCacheObj: cache, DelayCall: DelayCall})
}

// 重时间计数器
func UpTime(szKey string) {
	if o, ok := delayClear.Load(szKey); ok {
		x1 := o.(*delayClearObj)
		x1.Time = time.Now().Unix()
		delayClear.Store(szKey, x1)
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
		x1.FnCbk()
		delayClear.Delete(szKey)
	}
}

// 单实例运行
var IsDo = make(chan struct{}, 1)

func DoSleep() {
	time.Sleep(4 * time.Second)
}

// 延时清理
func DoDelayClear() {
	IsDo <- struct{}{}
	Wg.Add(1)
	go func() {
		defer func() {
			<-IsDo
			Wg.Done()
		}()
		nN := time.Now().Unix()
		delayClear.Range(func(key, value any) bool {
			if nil == value {
				delayClear.Delete(key)
				return true
			}
			x1 := value.(*delayClearObj)
			n09 := nN - x1.Time
			//log.Printf("n09 = %d, now = %d, x1.Time = %d", n09, nN, x1.Time)
			if n09 >= x1.DelayCall {
				x1.FnCbk()
				delayClear.Delete(key)
				//log.Println("nuclei is closed : ", key)
			}
			return true
		})
	}()
	return
}
