package disk

import (
	"bytes"
	"strconv"
	"sync"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/iterator"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
)

const expSeparator = ";"

// LevelDB - represents a leveldb db implementation
type LevelDB struct {
	db *leveldb.DB
	sync.RWMutex
}

// OpenLevelDB - Opens the specified path
func OpenLevelDB(path string) (*LevelDB, error) {
	db, err := leveldb.OpenFile(path, &opt.Options{
		CompactionTableSize: 256 * Megabyte,
	})
	if err != nil {
		return nil, err
	}

	ldb := new(LevelDB)
	ldb.db = db

	return ldb, nil
}

// Size - returns the size of the database in bytes
func (ldb *LevelDB) Size() int64 {
	var stats leveldb.DBStats
	if nil != ldb.db.Stats(&stats) {
		return -1
	}
	size := int64(0)
	for _, v := range stats.LevelSizes {
		size += v
	}
	return size
}

// Close ...
func (ldb *LevelDB) Close() {
	ldb.db.Close()
}

// GC - runs the garbage collector
func (ldb *LevelDB) GC() error {
	return ldb.db.CompactRange(util.Range{})
}

// Incr - increment the key by the specified value
func (ldb *LevelDB) Incr(k string, by int64) (int64, error) {
	ldb.Lock()
	defer ldb.Unlock()

	val, err := ldb.get(k)
	if err != nil {
		val = []byte{}
	}

	valFloat, _ := strconv.ParseInt(string(val), 10, 64)
	valFloat += by

	err = ldb.set([]byte(k), intToByteSlice(valFloat), -1)
	if err != nil {
		return 0, err
	}

	return valFloat, nil
}

func intToByteSlice(v int64) []byte {
	return []byte(strconv.FormatInt(v, 10))
}

func (ldb *LevelDB) set(k, v []byte, ttl time.Duration) error {
	var expires int64
	if ttl > 0 {
		expires = time.Now().Add(ttl).Unix()
	}
	expiresBytes := append(intToByteSlice(expires), expSeparator[:]...)
	v = append(expiresBytes, v...)
	return ldb.db.Put(k, v, nil)
}

// Set - sets a key with the specified value and optional ttl
func (ldb *LevelDB) Set(k string, v []byte, ttl time.Duration) error {
	return ldb.set([]byte(k), v, ttl)
}

// MSet - sets multiple key-value pairs
func (ldb *LevelDB) MSet(data map[string][]byte) error {
	batch := new(leveldb.Batch)
	for k, v := range data {
		v = append([]byte("0;"), v...)
		batch.Put([]byte(k), v)
	}
	return ldb.db.Write(batch, nil)
}

func (ldb *LevelDB) get(k string) ([]byte, error) {
	var data []byte
	var err error

	delete := false

	item, err := ldb.db.Get([]byte(k), nil)
	if err != nil {
		return []byte{}, err
	}

	parts := bytes.SplitN(item, []byte(expSeparator), 2)
	expires, actual := parts[0], parts[1]

	if exp, _ := strconv.Atoi(string(expires)); exp > 0 && int(time.Now().Unix()) >= exp {
		delete = true
	} else {
		data = actual
	}

	if delete {
		errDelete := ldb.db.Delete([]byte(k), nil)
		if errDelete != nil {
			return data, errDelete
		}
		return data, ErrNotFound
	}

	return data, nil
}

// Get - fetches the value of the specified k
func (ldb *LevelDB) Get(k string) ([]byte, error) {
	return ldb.get(k)
}

// MGet - fetch multiple values of the specified keys
func (ldb *LevelDB) MGet(keys []string) [][]byte {
	var data [][]byte
	for _, key := range keys {
		val, err := ldb.get(key)
		if err != nil {
			data = append(data, []byte{})
			continue
		}
		data = append(data, val)
	}
	return data
}

// TTL - returns the time to live of the specified key's value
func (ldb *LevelDB) TTL(key string) int64 {
	item, err := ldb.db.Get([]byte(key), nil)
	if err != nil {
		return -2
	}

	parts := bytes.SplitN(item, []byte(expSeparator), 2)
	exp, _ := strconv.Atoi(string(parts[0]))
	if exp == 0 {
		return -1
	}

	now := time.Now().Unix()
	if now >= int64(exp) {
		return -2
	}

	return int64(exp) - now
}

// MDel - removes key(s) from the store
func (ldb *LevelDB) MDel(keys []string) error {
	batch := new(leveldb.Batch)
	for _, key := range keys {
		batch.Delete([]byte(key))
	}
	return ldb.db.Write(batch, nil)
}

// Del - removes key from the store
func (ldb *LevelDB) Del(key string) error {
	return ldb.db.Delete([]byte(key), nil)
}

// Scan - iterate over the whole store using the handler function
func (ldb *LevelDB) Scan(scannerOpt ScannerOptions) error {
	var iter iterator.Iterator

	if scannerOpt.Offset == "" {
		iter = ldb.db.NewIterator(nil, nil)
	} else {
		iter = ldb.db.NewIterator(&util.Range{Start: []byte(scannerOpt.Offset)}, nil)
		if !scannerOpt.IncludeOffset {
			iter.Next()
		}
	}

	valid := func(k []byte) bool {
		if k == nil {
			return false
		}

		if scannerOpt.Prefix != "" && !bytes.HasPrefix(k, []byte(scannerOpt.Prefix)) {
			return false
		}

		return true
	}

	for iter.Next() {
		key := iter.Key()
		val := bytes.SplitN(iter.Value(), []byte(";"), 2)[1]
		if !valid(key) || scannerOpt.Handler(key, val) != nil {
			break
		}
	}

	iter.Release()

	return iter.Error()
}
