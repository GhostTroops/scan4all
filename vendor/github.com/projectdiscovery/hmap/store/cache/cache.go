package cache

import (
	"runtime"
	"sync"
	"time"
)

const (
	NoExpiration      time.Duration = -1
	DefaultExpiration time.Duration = 0
)

type Cache interface {
	SetWithExpiration(string, interface{}, time.Duration)
	Set(string, interface{})
	Get(string) (interface{}, bool)
	Delete(string)
	DeleteExpired()
	OnEvicted(func(string, interface{}))
	CloneItems() map[string]Item
	Scan(func([]byte, []byte) error)
	ItemCount() int
}

type CacheMemory struct {
	*cacheMemory
}

type cacheMemory struct {
	DefaultExpiration time.Duration
	Items             map[string]Item
	mu                sync.RWMutex
	onEvicted         func(string, interface{})
	janitor           *janitor
}

func (c *cacheMemory) SetWithExpiration(k string, x interface{}, d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.set(k, x, d)
}

func (c *cacheMemory) set(k string, x interface{}, d time.Duration) {
	var e int64
	if d == DefaultExpiration {
		d = c.DefaultExpiration
	}
	if d > 0 {
		e = time.Now().Add(d).UnixNano()
	}
	c.Items[k] = Item{
		Object:     x,
		Expiration: e,
	}
}

func (c *cacheMemory) Set(k string, x interface{}) {
	c.SetWithExpiration(k, x, c.DefaultExpiration)
}

func (c *cacheMemory) Get(k string) (interface{}, bool) {
	c.mu.RLock()
	item, found := c.Items[k]
	if !found {
		c.mu.RUnlock()
		return nil, false
	}
	if item.Expiration > 0 {
		if time.Now().UnixNano() > item.Expiration {
			c.mu.RUnlock()
			return nil, false
		}
	}
	c.mu.RUnlock()
	c.refresh(k)
	return item.Object, true
}

func (c *cacheMemory) refresh(k string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	item, found := c.Items[k]
	if !found {
		return false
	}
	item.Expiration = time.Now().Add(c.DefaultExpiration).UnixNano()
	return true
}

func (c *cacheMemory) Delete(k string) {
	c.mu.Lock()
	v, evicted := c.delete(k)
	c.mu.Unlock()
	if evicted {
		c.onEvicted(k, v)
	}
}

func (c *cacheMemory) delete(k string) (interface{}, bool) {
	if c.onEvicted != nil {
		if v, found := c.Items[k]; found {
			delete(c.Items, k)
			return v.Object, true
		}
	}
	delete(c.Items, k)
	return nil, false
}

// Delete all expired items from the cache.
func (c *cacheMemory) DeleteExpired() {
	var evictedItems []keyAndValue
	now := time.Now().UnixNano()
	c.mu.Lock()
	for k, v := range c.Items {
		// "Inlining" of expired
		if v.Expiration > 0 && now > v.Expiration {
			ov, evicted := c.delete(k)
			if evicted {
				evictedItems = append(evictedItems, keyAndValue{k, ov})
			}
		}
	}
	c.mu.Unlock()
	for _, v := range evictedItems {
		c.onEvicted(v.key, v.value)
	}
}

func (c *cacheMemory) OnEvicted(f func(string, interface{})) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onEvicted = f
}

func (c *cacheMemory) Scan(f func([]byte, []byte) error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for k, item := range c.Items {
		if f([]byte(k), item.Object.([]byte)) != nil {
			break
		}
	}
}

func (c *cacheMemory) CloneItems() map[string]Item {
	c.mu.RLock()
	defer c.mu.RUnlock()
	m := make(map[string]Item, len(c.Items))
	now := time.Now().UnixNano()
	for k, v := range c.Items {
		// "Inlining" of Expired
		if v.Expiration > 0 {
			if now > v.Expiration {
				continue
			}
		}
		m[k] = v
	}
	return m
}

func (c *cacheMemory) ItemCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	n := len(c.Items)

	return n
}

func (c *cacheMemory) Empty() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.Items = map[string]Item{}
}

func newCache(de time.Duration, m map[string]Item) *cacheMemory {
	if de == 0 {
		de = -1
	}
	c := &cacheMemory{
		DefaultExpiration: de,
		Items:             m,
	}
	return c
}

func newCacheWithJanitor(de time.Duration, ci time.Duration, m map[string]Item) *CacheMemory {
	c := newCache(de, m)
	w := &CacheMemory{
		cacheMemory: c,
	}
	if ci > 0 {
		runJanitor(c, ci)
		runtime.SetFinalizer(w, func(c *CacheMemory) {
			stopJanitor(c.cacheMemory)
		})
	}
	return w
}

func New(defaultExpiration, cleanupInterval time.Duration) *CacheMemory {
	items := make(map[string]Item)
	return newCacheWithJanitor(defaultExpiration, cleanupInterval, items)
}

func NewFrom(defaultExpiration, cleanupInterval time.Duration, items map[string]Item) *CacheMemory {
	return newCacheWithJanitor(defaultExpiration, cleanupInterval, items)
}
