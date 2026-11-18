package gcache

import (
	"time"

	"github.com/Mzack9999/gcache/internal/list"
)

// Constantly balances between LRU and LFU, to improve the combined result.
type ARC[K comparable, V any] struct {
	baseCache[K, V]
	items map[K]*arcItem[K, V]

	part int
	t1   *arcList[K]
	t2   *arcList[K]
	b1   *arcList[K]
	b2   *arcList[K]
}

func newARC[K comparable, V any](cb *CacheBuilder[K, V]) *ARC[K, V] {
	c := &ARC[K, V]{}
	buildCache(&c.baseCache, cb)

	c.init()
	c.loadGroup.cache = c
	return c
}

func (c *ARC[K, V]) init() {
	c.items = make(map[K]*arcItem[K, V], c.size)
	c.t1 = newARCList[K]()
	c.t2 = newARCList[K]()
	c.b1 = newARCList[K]()
	c.b2 = newARCList[K]()
}

func (c *ARC[K, V]) replace(key K) {
	if !c.isCacheFull() {
		return
	}
	var old K
	if c.t1.Len() > 0 && ((c.b2.Has(key) && c.t1.Len() == c.part) || (c.t1.Len() > c.part)) {
		old = c.t1.RemoveTail()
		c.b1.PushFront(old)
	} else if c.t2.Len() > 0 {
		old = c.t2.RemoveTail()
		c.b2.PushFront(old)
	} else {
		old = c.t1.RemoveTail()
		c.b1.PushFront(old)
	}
	item, ok := c.items[old]
	if ok {
		delete(c.items, old)
		if c.evictedFunc != nil {
			c.evictedFunc(item.key, item.value)
		}
	}
}

func (c *ARC[K, V]) Set(key K, value V) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.set(key, value)
	return err
}

// Set a new key-value pair with an expiration time
func (c *ARC[K, V]) SetWithExpire(key K, value V, expiration time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	item, err := c.set(key, value)
	if err != nil {
		return err
	}

	t := c.clock.Now().Add(expiration)
	item.expiration = &t
	return nil
}

func (c *ARC[K, V]) set(key K, value V) (*arcItem[K, V], error) {
	var err error
	if c.serializeFunc != nil {
		value, err = c.serializeFunc(key, value)
		if err != nil {
			return nil, err
		}
	}

	item, ok := c.items[key]
	if ok {
		item.value = value
	} else {
		item = &arcItem[K, V]{
			clock: c.clock,
			key:   key,
			value: value,
		}
		c.items[key] = item
	}

	if c.expiration != nil {
		t := c.clock.Now().Add(*c.expiration)
		item.expiration = &t
	}

	defer func() {
		if c.addedFunc != nil {
			c.addedFunc(key, value)
		}
	}()

	if c.t1.Has(key) || c.t2.Has(key) {
		return item, nil
	}

	if elt := c.b1.Lookup(key); elt != nil {
		c.setPart(minInt(c.size, c.part+maxInt(c.b2.Len()/c.b1.Len(), 1)))
		c.replace(key)
		c.b1.Remove(key, elt)
		c.t2.PushFront(key)
		return item, nil
	}

	if elt := c.b2.Lookup(key); elt != nil {
		c.setPart(maxInt(0, c.part-maxInt(c.b1.Len()/c.b2.Len(), 1)))
		c.replace(key)
		c.b2.Remove(key, elt)
		c.t2.PushFront(key)
		return item, nil
	}

	if c.isCacheFull() && c.t1.Len()+c.b1.Len() == c.size {
		if c.t1.Len() < c.size {
			c.b1.RemoveTail()
			c.replace(key)
		} else {
			pop := c.t1.RemoveTail()
			item, ok := c.items[pop]
			if ok {
				delete(c.items, pop)
				if c.evictedFunc != nil {
					c.evictedFunc(item.key, item.value)
				}
			}
		}
	} else {
		total := c.t1.Len() + c.b1.Len() + c.t2.Len() + c.b2.Len()
		if total >= c.size {
			if total == (2 * c.size) {
				if c.b2.Len() > 0 {
					c.b2.RemoveTail()
				} else {
					c.b1.RemoveTail()
				}
			}
			c.replace(key)
		}
	}
	c.t1.PushFront(key)
	return item, nil
}

// Get a value from cache pool using key if it exists. If not exists and it has LoaderFunc, it will generate the value using you have specified LoaderFunc method returns value.
func (c *ARC[K, V]) Get(key K) (V, error) {
	v, err := c.get(key, false)
	if err == KeyNotFoundError {
		return c.getWithLoader(key, true)
	}
	return v, err
}

// GetIFPresent gets a value from cache pool using key if it exists.
// If it does not exists key, returns KeyNotFoundError.
// And send a request which refresh value for specified key if cache object has LoaderFunc.
func (c *ARC[K, V]) GetIFPresent(key K) (V, error) {
	v, err := c.get(key, false)
	if err == KeyNotFoundError {
		return c.getWithLoader(key, false)
	}
	return v, err
}

func (c *ARC[K, V]) get(key K, onLoad bool) (V, error) {
	v, err := c.getValue(key, onLoad)
	if err != nil {
		return c.nilV, err
	}
	if c.deserializeFunc != nil {
		return c.deserializeFunc(key, v)
	}
	return v, nil
}

func (c *ARC[K, V]) getValue(key K, onLoad bool) (V, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elt := c.t1.Lookup(key); elt != nil {
		c.t1.Remove(key, elt)
		item := c.items[key]
		if !item.IsExpired(nil) {
			c.t2.PushFront(key)
			if !onLoad {
				c.stats.IncrHitCount()
			}
			c.autoLease(item)
			return item.value, nil
		} else {
			delete(c.items, key)
			c.b1.PushFront(key)
			if c.evictedFunc != nil {
				c.evictedFunc(item.key, item.value)
			}
		}
	}
	if elt := c.t2.Lookup(key); elt != nil {
		item := c.items[key]
		if !item.IsExpired(nil) {
			c.t2.MoveToFront(elt)
			if !onLoad {
				c.stats.IncrHitCount()
			}
			c.autoLease(item)
			return item.value, nil
		} else {
			delete(c.items, key)
			c.t2.Remove(key, elt)
			c.b2.PushFront(key)
			if c.evictedFunc != nil {
				c.evictedFunc(item.key, item.value)
			}
		}
	}

	if !onLoad {
		c.stats.IncrMissCount()
	}
	return c.nilV, KeyNotFoundError
}

func (c *ARC[K, V]) getWithLoader(key K, isWait bool) (V, error) {
	if c.loaderExpireFunc == nil {
		return c.nilV, KeyNotFoundError
	}
	value, _, err := c.load(key, func(v V, expiration *time.Duration, e error) (V, error) {
		if e != nil {
			return c.nilV, e
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		item, err := c.set(key, v)
		if err != nil {
			return c.nilV, err
		}
		if expiration != nil {
			t := c.clock.Now().Add(*expiration)
			item.expiration = &t
		}
		return v, nil
	}, isWait)
	if err != nil {
		return c.nilV, err
	}
	return value, nil
}

// Has checks if key exists in cache
func (c *ARC[K, V]) Has(key K) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := time.Now()
	return c.has(key, &now)
}

func (c *ARC[K, V]) has(key K, now *time.Time) bool {
	item, ok := c.items[key]
	if !ok {
		return false
	}
	return !item.IsExpired(now)
}

// Remove removes the provided key from the cache.
func (c *ARC[K, V]) Remove(key K) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.remove(key)
}

func (c *ARC[K, V]) remove(key K) bool {
	if elt := c.t1.Lookup(key); elt != nil {
		c.t1.Remove(key, elt)
		item := c.items[key]
		delete(c.items, key)
		c.b1.PushFront(key)
		if c.evictedFunc != nil {
			c.evictedFunc(key, item.value)
		}
		return true
	}

	if elt := c.t2.Lookup(key); elt != nil {
		c.t2.Remove(key, elt)
		item := c.items[key]
		delete(c.items, key)
		c.b2.PushFront(key)
		if c.evictedFunc != nil {
			c.evictedFunc(key, item.value)
		}
		return true
	}

	return false
}

// GetALL returns all key-value pairs in the cache.
func (c *ARC[K, V]) GetALL(checkExpired bool) map[K]V {
	c.mu.RLock()
	defer c.mu.RUnlock()
	items := make(map[K]V, len(c.items))
	now := time.Now()
	for k, item := range c.items {
		if !checkExpired || c.has(k, &now) {
			items[k] = item.value
		}
	}
	return items
}

// Keys returns a slice of the keys in the cache.
func (c *ARC[K, V]) Keys(checkExpired bool) []K {
	c.mu.RLock()
	defer c.mu.RUnlock()
	keys := make([]K, 0, len(c.items))
	now := time.Now()
	for k := range c.items {
		if !checkExpired || c.has(k, &now) {
			keys = append(keys, k)
		}
	}
	return keys
}

// Len returns the number of items in the cache.
func (c *ARC[K, V]) Len(checkExpired bool) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !checkExpired {
		return len(c.items)
	}
	var length int
	now := time.Now()
	for k := range c.items {
		if c.has(k, &now) {
			length++
		}
	}
	return length
}

// Purge is used to completely clear the cache
func (c *ARC[K, V]) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.purgeVisitorFunc != nil {
		for _, item := range c.items {
			c.purgeVisitorFunc(item.key, item.value)
		}
	}

	c.init()
}

func (c *ARC[K, V]) setPart(p int) {
	if c.isCacheFull() {
		c.part = p
	}
}

func (c *ARC[K, V]) isCacheFull() bool {
	return (c.t1.Len() + c.t2.Len()) == c.size
}

func (c *ARC[K, V]) autoLease(item *arcItem[K, V]) {
	if item.expiration == nil {
		return
	}
	if c.lease == nil {
		return
	}
	t := item.clock.Now().Add(*c.lease)
	item.expiration = &t
}

// IsExpired returns boolean value whether this item is expired or not.
func (it *arcItem[K, V]) IsExpired(now *time.Time) bool {
	if it.expiration == nil {
		return false
	}
	if now == nil {
		t := it.clock.Now()
		now = &t
	}
	return it.expiration.Before(*now)
}

type arcList[K comparable] struct {
	l    *list.List[K]
	keys map[K]*list.Element[K]
}

type arcItem[K comparable, V any] struct {
	clock      Clock
	key        K
	value      V
	expiration *time.Time
}

func newARCList[K comparable]() *arcList[K] {
	return &arcList[K]{
		l:    list.New[K](),
		keys: make(map[K]*list.Element[K]),
	}
}

func (al *arcList[K]) Has(key K) bool {
	_, ok := al.keys[key]
	return ok
}

func (al *arcList[K]) Lookup(key K) *list.Element[K] {
	elt := al.keys[key]
	return elt
}

func (al *arcList[K]) MoveToFront(elt *list.Element[K]) {
	al.l.MoveToFront(elt)
}

func (al *arcList[K]) PushFront(key K) {
	if elt, ok := al.keys[key]; ok {
		al.l.MoveToFront(elt)
		return
	}
	elt := al.l.PushFront(key)
	al.keys[key] = elt
}

func (al *arcList[K]) Remove(key K, elt *list.Element[K]) {
	delete(al.keys, key)
	al.l.Remove(elt)
}

func (al *arcList[K]) RemoveTail() K {
	elt := al.l.Back()
	al.l.Remove(elt)

	key := elt.Value
	delete(al.keys, key)

	return key
}

func (al *arcList[K]) Len() int {
	return al.l.Len()
}
