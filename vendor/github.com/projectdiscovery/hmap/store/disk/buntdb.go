package disk

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/buntdb"
)

// BuntDB - represents a BuntDB implementation
type BuntDB struct {
	db *buntdb.DB
	sync.RWMutex
}

// OpenBuntDB - Opens the specified path
func OpenBuntDB(path string) (*BuntDB, error) {
	db, err := buntdb.Open(path)
	if err != nil {
		return nil, err
	}

	bdb := new(BuntDB)
	bdb.db = db

	return bdb, nil
}

// Size - Not implemented
func (bdb *BuntDB) Size() int64 {
	return 0
}

// Close
func (bdb *BuntDB) Close() {
	bdb.db.Close()
}

// GC - runs the garbage collector
func (bdb *BuntDB) GC() error {
	return bdb.db.Shrink()
}

// Incr - increment the key by the specified value
func (bdb *BuntDB) Incr(k string, by int64) (int64, error) {
	bdb.Lock()
	defer bdb.Unlock()

	var valP int64
	err := bdb.db.Update(func(tx *buntdb.Tx) error {
		val, err := tx.Get(k)
		if err != nil {
			return err
		}
		valP, _ = strconv.ParseInt(val, 10, 64)
		valP += by
		_, _, err = tx.Set(k, strconv.FormatInt(valP, 10), nil)
		return err
	})

	return valP, err
}

// Set - sets a key with the specified value and optional ttl
func (bdb *BuntDB) Set(k string, v []byte, ttl time.Duration) error {
	return bdb.db.Update(func(tx *buntdb.Tx) error {
		opts := new(buntdb.SetOptions)
		opts.Expires = ttl > 0
		opts.TTL = ttl
		_, _, err := tx.Set(k, string(v), opts)
		return err
	})
}

// MSet - sets multiple key-value pairs
func (bdb *BuntDB) MSet(data map[string][]byte) error {
	return bdb.db.Update(func(tx *buntdb.Tx) error {
		for k, v := range data {
			if _, _, err := tx.Set(k, string(v), nil); err != nil {
				return err
			}
		}
		return nil
	})
}

// Get - fetches the value of the specified k
func (bdb *BuntDB) Get(k string) ([]byte, error) {
	var data []byte
	err := bdb.db.View(func(tx *buntdb.Tx) error {
		val, err := tx.Get(k)
		if err != nil {
			return err
		}
		data = []byte(val)
		return nil
	})
	return data, err
}

// MGet - fetch multiple values of the specified keys
func (bdb *BuntDB) MGet(keys []string) [][]byte {
	var data [][]byte
	_ = bdb.db.View(func(tx *buntdb.Tx) error {
		for _, k := range keys {
			val, err := tx.Get(k)
			if err != nil {
				data = append(data, []byte{})
			} else {
				data = append(data, []byte(val))
			}
		}
		return nil
	})
	return data
}

// TTL - returns the time to live of the specified key's value
func (bdb *BuntDB) TTL(key string) int64 {
	var ttl int64
	_ = bdb.db.View(func(tx *buntdb.Tx) error {
		d, err := tx.TTL(key)
		if err != nil {
			return err
		}
		ttl = int64(d)
		return nil
	})
	return ttl
}

// MDel - removes key(s) from the store
func (bdb *BuntDB) MDel(keys []string) error {
	return bdb.db.Update(func(tx *buntdb.Tx) error {
		for _, k := range keys {
			if _, err := tx.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// Del - removes key from the store
func (bdb *BuntDB) Del(key string) error {
	return bdb.db.Update(func(tx *buntdb.Tx) error {
		_, err := tx.Delete(key)
		if err != nil {
			return err
		}
		return nil
	})
}

// Scan - iterate over the whole store using the handler function
func (bdb *BuntDB) Scan(opt ScannerOptions) error {
	valid := func(k, v string) bool {
		// Do not include offset item, skip this
		if !opt.IncludeOffset && len(opt.Offset) > 0 && k == opt.Offset {
			return true
		}

		// Do not has prefix, iterate out of bound, exit
		if len(opt.Prefix) > 0 && !strings.HasPrefix(k, opt.Prefix) {
			return false
		}

		if opt.Handler([]byte(k), []byte(v)) != nil {
			return false
		}
		return true
	}
	return bdb.db.View(func(tx *buntdb.Tx) error {
		// Has offset
		if len(opt.Offset) > 0 {
			return tx.AscendGreaterOrEqual("", opt.Offset, valid)
		}

		// Only prefix
		if len(opt.Prefix) > 0 && len(opt.Offset) == 0 {
			return tx.AscendKeys(opt.Prefix+"*", valid)
		}

		return tx.Ascend("", valid)
	})
}
