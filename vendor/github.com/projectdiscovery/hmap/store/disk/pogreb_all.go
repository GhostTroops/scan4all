//go:build !((arm || arm64) && windows)

package disk

import (
	"bytes"
	"strconv"
	"sync"
	"time"

	"github.com/akrylysov/pogreb"
)

func init() {
	OpenPogrebDB = openPogrebDB
}

// PogrebDB - represents a pogreb db implementation
type PogrebDB struct {
	db *pogreb.DB
	sync.RWMutex
}

// OpenPogrebDB - Opens the specified path
func openPogrebDB(path string) (DB, error) {
	db, err := pogreb.Open(path, nil)
	if err != nil {
		return nil, err
	}

	pdb := new(PogrebDB)
	pdb.db = db

	return pdb, nil
}

// Size - returns the size of the database in bytes
func (pdb *PogrebDB) Size() int64 {
	size, err := pdb.db.FileSize()
	if err != nil {
		return 0
	}
	return size
}

// Close ...
func (pdb *PogrebDB) Close() {
	pdb.db.Close()
}

// GC - runs the garbage collector
func (pdb *PogrebDB) GC() error {
	_, err := pdb.db.Compact()
	return err
}

// Incr - increment the key by the specified value
func (pdb *PogrebDB) Incr(k string, by int64) (int64, error) {
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

func (pdb *PogrebDB) set(k, v []byte, ttl time.Duration) error {
	var expires int64
	if ttl > 0 {
		expires = time.Now().Add(ttl).Unix()
	}
	expiresBytes := append(intToByteSlice(expires), expSeparator[:]...)
	v = append(expiresBytes, v...)
	return pdb.db.Put(k, v)
}

// Set - sets a key with the specified value and optional ttl
func (pdb *PogrebDB) Set(k string, v []byte, ttl time.Duration) error {
	return pdb.set([]byte(k), v, ttl)
}

// MSet - sets multiple key-value pairs
func (pdb *PogrebDB) MSet(data map[string][]byte) error {
	return nil
}

func (pdb *PogrebDB) get(k string) ([]byte, error) {
	var data []byte
	var err error

	delete := false

	item, err := pdb.db.Get([]byte(k))
	if err != nil {
		return []byte{}, err
	}

	if len(item) == 0 {
		return []byte{}, ErrNotFound
	}

	parts := bytes.SplitN(item, []byte(expSeparator), 2)
	expires, actual := parts[0], parts[1]

	if exp, _ := strconv.Atoi(string(expires)); exp > 0 && int(time.Now().Unix()) >= exp {
		delete = true
	}
	data = actual

	if delete {
		errDelete := pdb.db.Delete([]byte(k))
		if errDelete != nil {
			return data, errDelete
		}
		return data, ErrNotFound
	}
	return data, nil
}

// Get - fetches the value of the specified k
func (pdb *PogrebDB) Get(k string) ([]byte, error) {
	return pdb.get(k)
}

// MGet - fetch multiple values of the specified keys
func (pdb *PogrebDB) MGet(keys []string) [][]byte {
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
func (pdb *PogrebDB) TTL(key string) int64 {
	item, err := pdb.db.Get([]byte(key))
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
func (pdb *PogrebDB) MDel(keys []string) error {
	return nil
}

// Del - removes key from the store
func (pdb *PogrebDB) Del(key string) error {
	return pdb.db.Delete([]byte(key))
}

// Scan - iterate over the whole store using the handler function
func (pdb *PogrebDB) Scan(scannerOpt ScannerOptions) error {
	valid := func(k []byte) bool {
		if k == nil {
			return false
		}

		if scannerOpt.Prefix != "" && !bytes.HasPrefix(k, []byte(scannerOpt.Prefix)) {
			return false
		}

		return true
	}

	it := pdb.db.Items()
	for {
		key, val, err := it.Next()
		if err == pogreb.ErrIterationDone {
			break
		}
		if err != nil {
			return err
		}
		parts := bytes.SplitN(val, []byte(expSeparator), 2)
		_, data := parts[0], parts[1]
		if !valid(key) || scannerOpt.Handler(key, data) != nil {
			break
		}
	}

	return nil
}
