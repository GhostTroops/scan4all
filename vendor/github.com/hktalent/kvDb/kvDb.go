package kvDb

import (
	"github.com/json-iterator/go"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/iterator"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
	"log"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

type KvDb struct {
	db     *leveldb.DB
	dbPath string
	Opt    *opt.Options
	IsInit bool
}

func NewKvDb(dbPath string, opt *opt.Options) *KvDb {
	if "" == dbPath {
		dbPath = "db/kvDb"
	}
	x1 := &KvDb{dbPath: dbPath, IsInit: false, Opt: opt}
	x1.init()
	return x1
}

func (r *KvDb) log(a ...any) {
	log.Println(a...)
}

// &util.Range{Start: []byte("foo"), Limit: []byte("xoo")}
// util.BytesPrefix([]byte("foo-"))
func (r *KvDb) Iterator(fnCbk func(iterator.Iterator) bool, slice *util.Range) {
	iter := r.db.NewIterator(slice, nil)
	defer iter.Release()
	if nil != fnCbk {
		for iter.Next() {
			if !fnCbk(iter) {
				break
			}
		}
	}
}

// delete more key
func (r *KvDb) Delete(a ...any) bool {
	bRst := true
	for _, x := range a {
		if k, err := json.Marshal(x); nil == err {
			r.db.Delete(k, nil)
			bRst = bRst && true
		} else {
			bRst = bRst && false
			r.log("Delete error ", err)
		}
	}
	return bRst
}

// put
//  k,v,
//  k1,v2
//  kn,vn
func (r *KvDb) Put(a ...any) bool {
	bRst := 0 == len(a)%2
	if bRst {
		for i := 0; i < len(a); i += 2 {
			k, err := json.Marshal(a[i])
			v, err1 := json.Marshal(a[i+1])
			if nil == err && nil == err1 {
				if err := r.db.Put(k, v, nil); nil != err {
					r.log(err)
					bRst = bRst && false
				} else {
					bRst = bRst && true
				}
			} else {
				bRst = bRst && false
			}
		}
	}
	return bRst
}

// get more key,for fnCbk or out chan
func (r *KvDb) Get(out chan interface{}, fnCbk func([]byte), a ...any) {
	for _, x := range a {
		if d, err := json.Marshal(x); nil == err {
			if data, err := r.db.Get(d, nil); nil == err {
				if nil != fnCbk {
					fnCbk(data)
				} else {
					out <- data
				}
			} else {
				r.log("Get db.Get error ", err)
			}
		} else {
			r.log("Get json.Marshal error ", err)
		}
	}
}

func (r *KvDb) Close() {
	if nil != r.db {
		r.db.Close()
		r.db = nil
	}
}
func (r *KvDb) init() {
	if r.IsInit {
		return
	}
	if db, err := leveldb.OpenFile(r.dbPath, r.Opt); nil == err {
		r.IsInit = true
		r.db = db
	} else {
		r.log("init is error ", err)
	}
}
