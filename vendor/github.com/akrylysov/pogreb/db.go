package pogreb

import (
	"bytes"
	"context"
	"math"
	"os"
	"sync"
	"time"

	"github.com/akrylysov/pogreb/fs"
	"github.com/akrylysov/pogreb/internal/errors"
	"github.com/akrylysov/pogreb/internal/hash"
)

const (
	// MaxKeyLength is the maximum size of a key in bytes.
	MaxKeyLength = math.MaxUint16

	// MaxValueLength is the maximum size of a value in bytes.
	MaxValueLength = 512 << 20 // 512 MiB

	// MaxKeys is the maximum numbers of keys in the DB.
	MaxKeys = math.MaxUint32

	metaExt    = ".pmt"
	dbMetaName = "db" + metaExt
)

// DB represents the key-value storage.
// All DB methods are safe for concurrent use by multiple goroutines.
type DB struct {
	mu                sync.RWMutex // Allows multiple database readers or a single writer.
	opts              *Options
	index             *index
	datalog           *datalog
	lock              fs.LockFile // Prevents opening multiple instances of the same database.
	hashSeed          uint32
	metrics           *Metrics
	syncWrites        bool
	cancelBgWorker    context.CancelFunc
	closeWg           sync.WaitGroup
	compactionRunning int32 // Prevents running compactions concurrently.
}

type dbMeta struct {
	HashSeed uint32
}

// Open opens or creates a new DB.
// The DB must be closed after use, by calling Close method.
func Open(path string, opts *Options) (*DB, error) {
	opts = opts.copyWithDefaults(path)

	if err := os.MkdirAll(path, 0755); err != nil {
		return nil, err
	}

	// Try to acquire a file lock.
	lock, acquiredExistingLock, err := createLockFile(opts)
	if err != nil {
		if err == os.ErrExist {
			err = errLocked
		}
		return nil, errors.Wrap(err, "creating lock file")
	}
	clean := lock.Unlock
	defer func() {
		if clean != nil {
			_ = clean()
		}
	}()

	if acquiredExistingLock {
		// Lock file already existed, but the process managed to acquire it.
		// It means the database wasn't closed properly.
		// Start recovery process.
		if err := backupNonsegmentFiles(opts.FileSystem); err != nil {
			return nil, err
		}
	}

	index, err := openIndex(opts)
	if err != nil {
		return nil, errors.Wrap(err, "opening index")
	}

	datalog, err := openDatalog(opts)
	if err != nil {
		return nil, errors.Wrap(err, "opening datalog")
	}

	db := &DB{
		opts:       opts,
		index:      index,
		datalog:    datalog,
		lock:       lock,
		metrics:    &Metrics{},
		syncWrites: opts.BackgroundSyncInterval == -1,
	}
	if index.count() == 0 {
		// The index is empty, make a new hash seed.
		seed, err := hash.RandSeed()
		if err != nil {
			return nil, err
		}
		db.hashSeed = seed
	} else {
		if err := db.readMeta(); err != nil {
			return nil, errors.Wrap(err, "reading db meta")
		}
	}

	if acquiredExistingLock {
		if err := db.recover(); err != nil {
			return nil, errors.Wrap(err, "recovering")
		}
	}

	if db.opts.BackgroundSyncInterval > 0 || db.opts.BackgroundCompactionInterval > 0 {
		db.startBackgroundWorker()
	}

	clean = nil
	return db, nil
}

func cloneBytes(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func (db *DB) writeMeta() error {
	m := dbMeta{
		HashSeed: db.hashSeed,
	}
	return writeGobFile(db.opts.FileSystem, dbMetaName, m)
}

func (db *DB) readMeta() error {
	m := dbMeta{}
	if err := readGobFile(db.opts.FileSystem, dbMetaName, &m); err != nil {
		return err
	}
	db.hashSeed = m.HashSeed
	return nil
}

func (db *DB) hash(data []byte) uint32 {
	return hash.Sum32WithSeed(data, db.hashSeed)
}

// newNullableTicker is a wrapper around time.NewTicker that allows creating a nil ticker.
// A nil ticker never ticks.
func newNullableTicker(d time.Duration) (<-chan time.Time, func()) {
	if d > 0 {
		t := time.NewTicker(d)
		return t.C, t.Stop
	}
	return nil, func() {}
}

func (db *DB) startBackgroundWorker() {
	ctx, cancel := context.WithCancel(context.Background())
	db.cancelBgWorker = cancel
	db.closeWg.Add(1)

	go func() {
		defer db.closeWg.Done()

		syncC, syncStop := newNullableTicker(db.opts.BackgroundSyncInterval)
		defer syncStop()

		compactC, compactStop := newNullableTicker(db.opts.BackgroundCompactionInterval)
		defer compactStop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-syncC:
				if err := db.Sync(); err != nil {
					logger.Printf("error synchronizing database: %v", err)
				}
			case <-compactC:
				if cr, err := db.Compact(); err != nil {
					logger.Printf("error compacting database: %v", err)
				} else if cr.CompactedSegments > 0 {
					logger.Printf("compacted database: %+v", cr)
				}
			}
		}
	}()
}

// Get returns the value for the given key stored in the DB or nil if the key doesn't exist.
func (db *DB) Get(key []byte) ([]byte, error) {
	h := db.hash(key)
	db.metrics.Gets.Add(1)
	db.mu.RLock()
	defer db.mu.RUnlock()
	var retValue []byte
	err := db.index.get(h, func(sl slot) (bool, error) {
		if uint16(len(key)) != sl.keySize {
			return false, nil
		}
		slKey, value, err := db.datalog.readKeyValue(sl)
		if err != nil {
			return true, err
		}
		if bytes.Equal(key, slKey) {
			retValue = cloneBytes(value)
			return true, nil
		}
		db.metrics.HashCollisions.Add(1)
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return retValue, nil
}

// Has returns true if the DB contains the given key.
func (db *DB) Has(key []byte) (bool, error) {
	h := db.hash(key)
	found := false
	db.mu.RLock()
	defer db.mu.RUnlock()
	err := db.index.get(h, func(sl slot) (bool, error) {
		if uint16(len(key)) != sl.keySize {
			return false, nil
		}
		slKey, err := db.datalog.readKey(sl)
		if err != nil {
			return true, err
		}
		if bytes.Equal(key, slKey) {
			found = true
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return false, err
	}
	return found, nil
}

func (db *DB) put(sl slot, key []byte) error {
	return db.index.put(sl, func(cursl slot) (bool, error) {
		if uint16(len(key)) != cursl.keySize {
			return false, nil
		}
		slKey, err := db.datalog.readKey(cursl)
		if err != nil {
			return true, err
		}
		if bytes.Equal(key, slKey) {
			db.datalog.trackDel(cursl) // Overwriting existing key.
			return true, nil
		}
		return false, nil
	})
}

// Put sets the value for the given key. It updates the value for the existing key.
func (db *DB) Put(key []byte, value []byte) error {
	if len(key) > MaxKeyLength {
		return errKeyTooLarge
	}
	if len(value) > MaxValueLength {
		return errValueTooLarge
	}
	h := db.hash(key)
	db.metrics.Puts.Add(1)
	db.mu.Lock()
	defer db.mu.Unlock()

	segID, offset, err := db.datalog.put(key, value)
	if err != nil {
		return err
	}

	sl := slot{
		hash:      h,
		segmentID: segID,
		keySize:   uint16(len(key)),
		valueSize: uint32(len(value)),
		offset:    offset,
	}

	if err := db.put(sl, key); err != nil {
		return err
	}

	if db.syncWrites {
		return db.sync()
	}
	return nil
}

func (db *DB) del(h uint32, key []byte, writeWAL bool) error {
	err := db.index.delete(h, func(sl slot) (b bool, e error) {
		if uint16(len(key)) != sl.keySize {
			return false, nil
		}
		slKey, err := db.datalog.readKey(sl)
		if err != nil {
			return true, err
		}
		if bytes.Equal(key, slKey) {
			db.datalog.trackDel(sl)
			var err error
			if writeWAL {
				err = db.datalog.del(key)
			}
			return true, err
		}
		return false, nil
	})
	return err
}

// Delete deletes the given key from the DB.
func (db *DB) Delete(key []byte) error {
	h := db.hash(key)
	db.metrics.Dels.Add(1)
	db.mu.Lock()
	defer db.mu.Unlock()
	if err := db.del(h, key, true); err != nil {
		return err
	}
	if db.syncWrites {
		return db.sync()
	}
	return nil
}

// Close closes the DB.
func (db *DB) Close() error {
	if db.cancelBgWorker != nil {
		db.cancelBgWorker()
	}
	db.closeWg.Wait()
	db.mu.Lock()
	defer db.mu.Unlock()
	if err := db.writeMeta(); err != nil {
		return err
	}
	if err := db.datalog.close(); err != nil {
		return err
	}
	if err := db.index.close(); err != nil {
		return err
	}
	if err := db.lock.Unlock(); err != nil {
		return err
	}
	return nil
}

func (db *DB) sync() error {
	return db.datalog.sync()
}

// Items returns a new ItemIterator.
func (db *DB) Items() *ItemIterator {
	return &ItemIterator{db: db}
}

// Sync commits the contents of the database to the backing FileSystem.
func (db *DB) Sync() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.sync()
}

// Count returns the number of keys in the DB.
func (db *DB) Count() uint32 {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.index.count()
}

// Metrics returns the DB metrics.
func (db *DB) Metrics() *Metrics {
	return db.metrics
}

// FileSize returns the total size of the disk storage used by the DB.
func (db *DB) FileSize() (int64, error) {
	var size int64
	files, err := db.opts.FileSystem.ReadDir(".")
	if err != nil {
		return 0, err
	}
	for _, file := range files {
		size += file.Size()
	}
	return size, nil
}
