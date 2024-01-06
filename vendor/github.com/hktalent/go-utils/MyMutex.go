package go_utils

import "sync"

var lock1 sync.Mutex

type MyMutex struct {
	*sync.Mutex
	Name   string
	IsLock bool
	m      *map[string]*MyMutex
}

var (
	lockMap = map[string]*MyMutex{}
)

func GetLock(s string) *MyMutex {
	lock1.Lock()
	defer lock1.Unlock()
	if o, ok := lockMap[s]; ok {
		return o
	}
	return NewMyMutex(&lockMap, s)
}

func NewMyMutex(m1 *map[string]*MyMutex, Name string) *MyMutex {
	r := MyMutex{Name: Name}
	r.Mutex = &sync.Mutex{}
	(*m1)[Name] = &r
	r.m = m1
	return &r
}

func (r *MyMutex) Lock() *MyMutex {
	r.Mutex.Lock()
	r.IsLock = true
	return r
}
func (r *MyMutex) Unlock() {
	lock1.Lock()
	defer lock1.Unlock()
	if r.IsLock {
		r.Mutex.Unlock()
		if nil != r.m {
			delete(*r.m, r.Name)
		}
		r.IsLock = false
		r.m = nil
	}
}
