package disk

import (
	"bytes"
	"strconv"
	"sync"
	"time"

	"github.com/pkg/errors"

	bolt "go.etcd.io/bbolt"
)

// BBoltDB - represents a bbolt db implementation
type BBoltDB struct {
	db *bolt.DB
	sync.RWMutex
	BucketName string
}

// OpenBoltDB - Opens the specified path
func OpenBoltDBB(path string) (*BBoltDB, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}

	bbdb := new(BBoltDB)
	bbdb.db = db

	return bbdb, nil
}

// Size - returns the size of the database in bytes
func (b *BBoltDB) Size() int64 {
	// not implemented
	return 0
}

// Close ...
func (b *BBoltDB) Close() {
	b.db.Close()
}

// GC - runs the garbage collector
func (b *BBoltDB) GC() error {
	return ErrNotImplemented
}

// Incr - increment the key by the specified value
func (b *BBoltDB) Incr(k string, by int64) (int64, error) {
	return 0, ErrNotImplemented
}

func (b *BBoltDB) set(k, v []byte, ttl time.Duration) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		var expires int64
		if ttl > 0 {
			expires = time.Now().Add(ttl).Unix()
		}
		b, err := tx.CreateBucketIfNotExists([]byte(b.BucketName))
		if err != nil {
			return err
		}
		expiresBytes := append(intToByteSlice(expires), expSeparator[:]...)
		v = append(expiresBytes, v...)
		return b.Put(k, v)
	})
}

// Set - sets a key with the specified value and optional ttl
func (b *BBoltDB) Set(k string, v []byte, ttl time.Duration) error {
	return b.set([]byte(k), v, ttl)
}

// MSet - sets multiple key-value pairs
func (b *BBoltDB) MSet(data map[string][]byte) error {
	return ErrNotImplemented
}

func (b *BBoltDB) get(k string) ([]byte, error) {
	var data []byte
	delete := false

	return data, b.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(b.BucketName))
		if err != nil {
			return err
		}
		data = b.Get([]byte(k))
		if data == nil {
			return ErrNoData
		}
		parts := bytes.SplitN(data, []byte(expSeparator), 2)
		expires, actual := parts[0], parts[1]
		if exp, _ := strconv.Atoi(string(expires)); exp > 0 && int(time.Now().Unix()) >= exp {
			delete = true
		}
		data = actual

		if delete {
			return b.Delete([]byte(k))
		}

		return nil
	})
}

// Get - fetches the value of the specified k
func (b *BBoltDB) Get(k string) ([]byte, error) {
	return b.get(k)
}

// MGet - fetch multiple values of the specified keys
func (b *BBoltDB) MGet(keys []string) [][]byte {
	var data [][]byte
	for _, key := range keys {
		val, err := b.get(key)
		if err != nil {
			data = append(data, []byte{})
			continue
		}
		data = append(data, val)
	}
	return data
}

// TTL - returns the time to live of the specified key's value
func (b *BBoltDB) TTL(key string) int64 {
	item, err := b.get(key)
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
func (b *BBoltDB) MDel(keys []string) error {
	return ErrNotImplemented
}

// Del - removes key from the store
func (b *BBoltDB) Del(key string) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(b.BucketName))
		if err != nil {
			return err
		}
		return b.Delete([]byte(key))
	})
}

// Scan - iterate over the whole store using the handler function
func (b *BBoltDB) Scan(scannerOpt ScannerOptions) error {
	valid := func(k []byte) bool {
		if k == nil {
			return false
		}

		if scannerOpt.Prefix != "" && !bytes.HasPrefix(k, []byte(scannerOpt.Prefix)) {
			return false
		}

		return true
	}
	return b.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(b.BucketName))
		if b == nil {
			return errors.New("bucket not found")
		}
		c := b.Cursor()
		for key, val := c.First(); key != nil; key, val = c.Next() {
			parts := bytes.SplitN(val, []byte(expSeparator), 2)
			data := val
			if len(parts) == 2 {
				data = parts[1]
			}
			if !valid(key) || scannerOpt.Handler(key, data) != nil {
				break
			}
		}
		return nil
	})
}
