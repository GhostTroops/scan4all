package util

import "sync"

var CbkCc sync.Map

type CbkManagerImp struct {
	fnCbk []func()
}

func NewCbkManagerImp() *CbkManagerImp {
	return &CbkManagerImp{}
}

func (r *CbkManagerImp) add(cbk func()) {
	r.fnCbk = append(r.fnCbk, cbk)
}

func (r *CbkManagerImp) DoCbk() {
	for _, c := range r.fnCbk {
		c()
	}
}

func DoCbk(k string) {
	if v, ok := CbkCc.Load(k); ok {
		v.(*CbkManagerImp).DoCbk()
	}
	CbkCc.Delete(k)
}

// 注册统一的回调
func RegCbk(k string, cbk func()) {
	var c1 *CbkManagerImp
	var v any
	var ok bool
	if v, ok = CbkCc.Load(k); !ok {
		c1 = NewCbkManagerImp()
	} else {
		c1 = v.(*CbkManagerImp)
	}
	c1.add(cbk)
}
