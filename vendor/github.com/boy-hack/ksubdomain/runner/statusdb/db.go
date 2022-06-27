package statusdb

import (
	"sync"
	"sync/atomic"
	"time"
)

type Item struct {
	Domain      string    // 查询域名
	Dns         string    // 查询dns
	Time        time.Time // 发送时间
	Retry       int       // 重试次数
	DomainLevel int       // 域名层级
}

type StatusDb struct {
	Items  sync.Map
	length int64
}

// 内存简易读写数据库，自带锁机制
func CreateMemoryDB() *StatusDb {
	db := &StatusDb{
		Items:  sync.Map{},
		length: 0,
	}
	return db
}
func (r *StatusDb) Add(domain string, tableData Item) {
	r.Items.Store(domain, tableData)
	atomic.AddInt64(&r.length, 1)
}
func (r *StatusDb) Set(domain string, tableData Item) {
	r.Items.Store(domain, tableData)
}
func (r *StatusDb) Get(domain string) (Item, bool) {
	v, ok := r.Items.Load(domain)
	if !ok {
		return Item{}, false
	}
	return v.(Item), ok
}
func (r *StatusDb) Length() int64 {
	return r.length
}
func (r *StatusDb) Del(domain string) {
	//r.Mu.Lock()
	//defer r.Mu.Unlock()
	_, ok := r.Items.LoadAndDelete(domain)
	if ok {
		atomic.AddInt64(&r.length, -1)
	}
}

func (r *StatusDb) Scan(f func(key string, value Item) error) {
	r.Items.Range(func(key, value interface{}) bool {
		k := key.(string)
		item := value.(Item)
		f(k, item)
		return true
	})
}
func (r *StatusDb) Close() {

}
