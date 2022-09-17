package disk

import (
	"bytes"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/dgraph-io/badger"
)

// BadgerDB - represents a badger db implementation
type BadgerDB struct {
	db *badger.DB
	sync.RWMutex
}

// OpenPogrebDB - Opens the specified path
func OpenBadgerDB(path string) (*BadgerDB, error) {
	badgerOptions := badger.DefaultOptions(path)
	badgerOptions.EventLogging = false
	badgerOptions.Logger = nil
	db, err := badger.Open(badgerOptions)
	if err != nil {
		return nil, err
	}

	bdb := new(BadgerDB)
	bdb.db = db

	return bdb, nil
}

// Size - returns the size of the database in bytes
func (bdb *BadgerDB) Size() int64 {
	lsm, vlog := bdb.db.Size()
	return lsm + vlog
}

// Close ...
func (bdb *BadgerDB) Close() {
	bdb.db.Close()
}

// GC - runs the garbage collector
func (bdb *BadgerDB) GC() error {
	return bdb.db.Flatten(1)
}

// Incr - increment the key by the specified value
func (bdb *BadgerDB) Incr(k string, by int64) (int64, error) {
	return 0, ErrNotImplemented
}

func (bdb *BadgerDB) set(k, v []byte, ttl time.Duration) error {
	return bdb.db.Update(func(txn *badger.Txn) error {
		var expires int64
		if ttl > 0 {
			expires = time.Now().Add(ttl).Unix()
		}
		expiresBytes := append(intToByteSlice(expires), expSeparator[:]...)
		v = append(expiresBytes, v...)
		return txn.Set(k, v)
	})
}

// Set - sets a key with the specified value and optional ttl
func (bdb *BadgerDB) Set(k string, v []byte, ttl time.Duration) error {
	return bdb.set([]byte(k), v, ttl)
}

// MSet - sets multiple key-value pairs
func (bdb *BadgerDB) MSet(data map[string][]byte) error {
	return ErrNotImplemented
}

func (bdb *BadgerDB) get(k string) ([]byte, error) {
	var data []byte
	delete := false
	return data, bdb.db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(k))
		if err != nil {
			return err
		}

		data, err = item.ValueCopy(nil)
		if err != nil {
			return err
		}
		parts := bytes.SplitN(data, []byte(expSeparator), 2)
		if len(data) == 2 {
			return errors.New("couldn't retrieve data")
		}
		expires, actual := parts[0], parts[1]
		if exp, _ := strconv.Atoi(string(expires)); exp > 0 && int(time.Now().Unix()) >= exp {
			delete = true
		} else {
			data = actual
		}

		if delete {
			return txn.Delete([]byte(k))
		}

		return nil
	})
}

// Get - fetches the value of the specified k
func (bdb *BadgerDB) Get(k string) ([]byte, error) {
	return bdb.get(k)
}

// MGet - fetch multiple values of the specified keys
func (bdb *BadgerDB) MGet(keys []string) [][]byte {
	var data [][]byte
	for _, key := range keys {
		val, err := bdb.get(key)
		if err != nil {
			data = append(data, []byte{})
			continue
		}
		data = append(data, val)
	}
	return data
}

// TTL - returns the time to live of the specified key's value
func (bdb *BadgerDB) TTL(key string) int64 {
	item, err := bdb.get(key)
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
func (bdb *BadgerDB) MDel(keys []string) error {
	return nil
}

// Del - removes key from the store
func (bdb *BadgerDB) Del(key string) error {
	return bdb.db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	})
}

// Scan - iterate over the whole store using the handler function
func (bdb *BadgerDB) Scan(scannerOpt ScannerOptions) error {
	valid := func(k []byte) bool {
		if k == nil {
			return false
		}

		if scannerOpt.Prefix != "" && !bytes.HasPrefix(k, []byte(scannerOpt.Prefix)) {
			return false
		}

		return true
	}

	return bdb.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := item.KeyCopy(nil)
			val, _ := item.ValueCopy(nil)
			isValid := valid(key)
			errHandler := scannerOpt.Handler(key, val)
			if !isValid || errHandler != nil {
				return errHandler
			}
		}

		return nil
	})
}
