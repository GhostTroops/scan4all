package smap

import (
	"sync"
)

type SMap struct {
	value sync.Map
}

func New() *SMap {
	return &SMap{sync.Map{}}
}

func (s *SMap) Set(key interface{}, value interface{}) {
	s.value.Store(key, value)
}

func (s *SMap) Get(key interface{}) (value interface{}, ok bool) {
	return s.value.Load(key)
}

func (s *SMap) Delete(key interface{}) {
	s.value.Delete(key)
}

func (s *SMap) Length() int {
	var i int
	f := func(key, value interface{}) bool {
		i = i + 1
		return true
	}
	s.value.Range(f)
	return i
}

func (s *SMap) Exist(key interface{}) bool {
	if _, ok := s.value.Load(key); ok {
		return true
	}
	return false
}

func (s *SMap) Peek() interface{} {
	var i interface{}
	f := func(key, value interface{}) bool {
		i = value
		return false
	}
	s.value.Range(f)
	return i
}

func (s *SMap) Range(f func(key interface{}, value interface{}) bool) {
	s.value.Range(f)
}

//func handler(key, value interface{}) bool {
//	fmt.Printf("Name :%s %s\n", key, value)
//	return true
//}

//遍历，传入一个函数，遍历的时候函数返回false则停止遍历
//s.value.Range(handler)
