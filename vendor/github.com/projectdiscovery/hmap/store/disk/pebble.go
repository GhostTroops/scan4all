package disk

import (
	"bytes"
	"strconv"
	"sync"
	"time"

	"github.com/cockroachdb/pebble"
)

// PebbleDB - represents a pebble db implementation
type PebbleDB struct {
	db *pebble.DB
	sync.RWMutex
}

// OpenPogrebDB - Opens the specified path
func OpenPebbleDB(path string) (*PebbleDB, error) {
	db, err := pebble.Open(path, &pebble.Options{})
	if err != nil {
		return nil, err
	}

	pdb := new(PebbleDB)
	pdb.db = db

	return pdb, nil
}

// Size - returns the size of the database in bytes
func (pdb *PebbleDB) Size() int64 {
	metrics := pdb.db.Metrics()
	if metrics == nil {
		return 0
	}
	return metrics.Total().Size
}

// Close ...
func (pdb *PebbleDB) Close() {
	pdb.db.Close()
}

// GC - runs the garbage collector
func (pdb *PebbleDB) GC() error {
	// find first and last key
	iter := pdb.db.NewIter(&pebble.IterOptions{})
	first := iter.Key()
	var last []byte
	for iter.Next() {
		if iter.Last() {
			last = iter.Key()
		}
	}
	return pdb.db.Compact(first, last)
}

// Incr - increment the key by the specified value
func (pdb *PebbleDB) Incr(k string, by int64) (int64, error) {
	pdb.Lock()
	defer pdb.Unlock()

	val, err := pdb.get(k)
	if err != nil {
		val = []byte{}
	}

	valFloat, _ := strconv.ParseInt(string(val), 10, 64)
	valFloat += by

	err = pdb.set([]byte(k), intToByteSlice(valFloat), -1)
	if err != nil {
		return 0, err
	}

	return valFloat, nil
}

func (pdb *PebbleDB) set(k, v []byte, ttl time.Duration) error {
	var expires int64
	if ttl > 0 {
		expires = time.Now().Add(ttl).Unix()
	}
	expiresBytes := append(intToByteSlice(expires), expSeparator[:]...)
	v = append(expiresBytes, v...)
	return pdb.db.Set(k, v, pebble.Sync)
}

// Set - sets a key with the specified value and optional ttl
func (pdb *PebbleDB) Set(k string, v []byte, ttl time.Duration) error {
	return pdb.set([]byte(k), v, ttl)
}

// MSet - sets multiple key-value pairs
func (pdb *PebbleDB) MSet(data map[string][]byte) error {
	return nil
}

func (pdb *PebbleDB) get(k string) ([]byte, error) {
	var data []byte
	var err error

	delete := false

	s, closer, err := pdb.db.Get([]byte(k))
	if err != nil {
		return []byte{}, err
	}
	defer closer.Close()

	// make a copy of the byte slice as we need to return it safely
	item := append(s[:0:0], s...)

	parts := bytes.SplitN(item, []byte(expSeparator), 2)
	expires, actual := parts[0], parts[1]

	if exp, _ := strconv.Atoi(string(expires)); exp > 0 && int(time.Now().Unix()) >= exp {
		delete = true
	} else {
		data = actual
	}

	if delete {
		err := pdb.db.Delete([]byte(k), pebble.Sync)
		if err != nil {
			return data, err
		}
		return data, ErrNotFound
	}

	return data, nil
}

// Get - fetches the value of the specified k
func (pdb *PebbleDB) Get(k string) ([]byte, error) {
	return pdb.get(k)
}

// MGet - fetch multiple values of the specified keys
func (pdb *PebbleDB) MGet(keys []string) [][]byte {
	var data [][]byte
	for _, key := range keys {
		val, err := pdb.get(key)
		if err != nil {
			data = append(data, []byte{})
			continue
		}
		data = append(data, val)
	}
	return data
}

// TTL - returns the time to live of the specified key's value
func (pdb *PebbleDB) TTL(key string) int64 {
	item, closer, err := pdb.db.Get([]byte(key))
	if err != nil {
		return -2
	}
	defer closer.Close()

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
func (pdb *PebbleDB) MDel(keys []string) error {
	return nil
}

// Del - removes key from the store
func (pdb *PebbleDB) Del(key string) error {
	return pdb.db.Delete([]byte(key), pebble.Sync)
}

// Scan - iterate over the whole store using the handler function
func (pdb *PebbleDB) Scan(scannerOpt ScannerOptions) error {
	iter := pdb.db.NewIter(nil)
	for iter.First(); iter.Valid(); iter.Next() {
		key, val := iter.Key(), iter.Value()
		if scannerOpt.Handler(key, val) != nil {
			break
		}
	}

	return nil
}
