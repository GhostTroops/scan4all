package util

import (
	"encoding/json"
	"github.com/dgraph-io/badger"
	"log"
	"os"
	"runtime"
)

var Cache1 *KvDbOp

// https://colobu.com/2017/10/11/badger-a-performant-k-v-store/
// https://juejin.cn/post/6844903814571491335
type KvDbOp struct {
	DbConn *badger.DB
}

func NewKvDbOp() *KvDbOp {
	if nil != Cache1 && nil != Cache1.DbConn {
		return Cache1
	}
	Cache1 = &KvDbOp{}
	CacheName11 := ".DbCache"
	s1 := GetVal(CacheName)
	if "" != s1 {
		CacheName11 = s1
	}
	if runtime.GOOS == "windows" {
		os.RemoveAll(CacheName11)
	}
	Mkdirs(CacheName11)
	if nil != Cache1.Init(CacheName11) {
		os.RemoveAll(CacheName11)
		NewKvDbOp()
	}
	return Cache1
}
func (r *KvDbOp) SetExpiresAt(ExpiresAt uint64) {
	r.DbConn.SetDiscardTs(ExpiresAt)
}

func (r *KvDbOp) Init(szDb string) error {
	opts := badger.DefaultOptions(szDb)
	opts.CompactL0OnClose = true
	opts.EventLogging = false
	opts.Logger = nil
	opts.LevelOneSize = 256 << 10
	opts.LevelSizeMultiplier = 20
	db, err := badger.Open(opts)
	if nil != err {
		log.Printf("Init2 k-v db cannot open multiple processes at the same time, or please delete the %s directory and try again: %v", szDb, err)
		return err
	}
	r.DbConn = db
	return nil
}

func (r *KvDbOp) Delete(key string) error {
	err := r.DbConn.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	})
	return err
}

func (r *KvDbOp) Close() {
	if nil != r.DbConn {
		r.DbConn.Close()
	}
}

// https://www.modb.pro/db/87317
func (r *KvDbOp) GetKeyForData(key string) (szRst []byte) {
	data, err := r.Get(key)
	if nil != err {
		//log.Println("GetKeyForData ", key, " is err ", err)
		return []byte{}
	}
	return data
}

// https://www.modb.pro/db/87317
func (r *KvDbOp) Get(key string) (szRst []byte, err error) {
	err = NewKvDbOp().DbConn.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		// val, err := item.Value()
		err = item.Value(func(val []byte) error {
			szRst = val
			return nil
		})
		return err
	})
	return szRst, err
}
func PutAny[T any](key string, data T) {
	if "" == key {
		return
	}
	d, err := json.Marshal(data)
	if nil == err && nil != Cache1 {
		Cache1.Put(key, d)
	}
}

func GetAny[T any](key string) (T, error) {
	var t1 T
	data, err := Cache1.Get(key)
	if nil == err {
		json.Unmarshal(data, &t1)
		return t1, nil
	}
	return t1, err
}

func (r *KvDbOp) Put(key string, data []byte) {
	err := r.DbConn.Update(func(txn *badger.Txn) error {
		err := txn.Set([]byte(key), data)
		if err == badger.ErrTxnTooBig {
			_ = txn.Commit()
		}
		return err
	})
	if err != nil {
	}
}

// 调整初始化顺序
// 初始化 kvDb
func init3() {
	NewKvDbOp()
}
