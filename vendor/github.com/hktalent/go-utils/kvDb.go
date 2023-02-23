package go_utils

import (
	"github.com/coreos/etcd/raft"
	"github.com/dgraph-io/badger"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"time"
)

// https://colobu.com/2017/10/11/badger-a-performant-k-v-store/
// https://juejin.cn/post/6844903814571491335
// key-value db chache
type KvCachedb struct {
	DbConn *badger.DB
}

var Cache1 *KvCachedb

// 获取一个
func NewKvCachedb() *KvCachedb {
	r := &KvCachedb{}
	r.InitKv()
	return r
}

func (r *KvCachedb) InitKv() *KvCachedb {
	if nil != r.DbConn {
		return r
	}
	CacheName11 := ".DbCache"
	s1 := GetVal(CacheName)
	if "" != s1 {
		CacheName11 = s1
	}
	if runtime.GOOS == "windows" {
		os.RemoveAll(CacheName11)
	}
	Mkdirs(CacheName11)
	r.init(CacheName11)
	return r
}

// SetDiscardTs sets a timestamp at or below which, any invalid or deleted versions can be discarded from the LSM tree, and thence from the value log to reclaim disk space. Can only be used with managed transactions.
func (r *KvCachedb) SetExpiresAt(ExpiresAt uint64) {
	r.DbConn.SetDiscardTs(ExpiresAt)
}

// init db name
func (r *KvCachedb) init(szDb string) error {
	opts := badger.DefaultOptions(szDb)
	opts.CompactL0OnClose = true
	opts.EventLogging = false
	opts.Logger = nil
	opts.LevelOneSize = 256 << 10
	opts.LevelSizeMultiplier = 20
	log1 := &raft.DefaultLogger{}
	if GetVal("ProductMod") == "release" {
		log1.Logger = log.New(ioutil.Discard, "", 0)
	} else {
		log1.Logger = log.New(os.Stderr, "kv-DB", log.LstdFlags)
	}
	opts.WithLogger(log1)
	db, err := badger.Open(opts)

	if nil != err {
		log.Printf("InitConfigFile k-v db cannot open multiple processes at the same time, or please delete the %s directory and try again: %v", szDb, err)
		return err
	}
	r.DbConn = db
	return nil
}

func (r *KvCachedb) Delete(key string) error {
	err := r.DbConn.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	})
	return err
}

func (r *KvCachedb) Close() {
	if nil != r.DbConn {
		r.DbConn.Close()
	}
}

// https://www.modb.pro/db/87317
func (r *KvCachedb) GetKeyForData(key string) (szRst []byte) {
	data, err := r.Get(key)
	if nil != err {
		//log.Println("GetKeyForData ", key, " is err ", err)
		return []byte{}
	}
	return data
}

// https://www.modb.pro/db/87317
func (r *KvCachedb) Get(key string) (szRst []byte, err error) {
	err = r.DbConn.View(func(txn *badger.Txn) error {
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
	d, err := Json.Marshal(data)
	if nil == err && nil != Cache1 {
		Cache1.Put(key, d)
	}
}

func GetAny[T any](key string) (T, error) {
	var t1 T
	data, err := Cache1.Get(key)
	if nil == err {
		Json.Unmarshal(data, &t1)
		return t1, nil
	}
	return t1, err
}

// r.DbConn.RunValueLogGC()
func (r *KvCachedb) PutWithTTL(key string, data []byte, ttl time.Duration) {
	err := r.DbConn.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry([]byte(key), data).WithMeta(byte(1)).WithTTL(ttl)
		err := txn.SetEntry(e)
		if err == badger.ErrTxnTooBig {
			_ = txn.Commit()
		}
		return err
	})
	if err != nil {
	}
}

func (r *KvCachedb) Put(key string, data []byte) {
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
func init() {
	RegInitFunc(func() {
		Cache1 = NewKvCachedb()
	})
}
