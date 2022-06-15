package filekv

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"strings"
	"sync"

	bloom "github.com/bits-and-blooms/bloom/v3"
	"github.com/projectdiscovery/fileutil"
)

// FileDB - represents a file db implementation
type FileDB struct {
	bm      *bloom.BloomFilter
	stats   Stats
	options Options
	tmpDb   *os.File
	db      *os.File
	sync.RWMutex
}

// Open a new file based db
func Open(options Options) (*FileDB, error) {
	var db *os.File
	if fileutil.FileExists(options.Path) {
		var err error
		db, err = os.Open(options.Path)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		db, err = os.Create(options.Path)
		if err != nil {
			return nil, err
		}
	}

	tmpDb, err := os.CreateTemp("", "")
	if err != nil {
		return nil, err
	}

	fdb := &FileDB{}

	if options.Dedupe {
		fdb.bm = bloom.NewWithEstimates(options.MaxItems, options.FPRatio)
	}

	fdb.options = options
	fdb.db = db
	fdb.tmpDb = tmpDb

	return fdb, nil
}

// Process added files/slices/elements
func (fdb *FileDB) Process() error {
	if err := fdb.tmpDb.Sync(); err != nil {
		return err
	}
	if _, err := fdb.tmpDb.Seek(0, 0); err != nil {
		return err
	}

	if fdb.options.Dedupe {
		fdb.bm = bloom.NewWithEstimates(fdb.stats.NumberOfAddedItems, fdb.options.FPRatio)
	}

	sc := bufio.NewScanner(fdb.tmpDb)
	maxCapacity := 512 * 1024 * 1024
	buf := make([]byte, maxCapacity)
	sc.Buffer(buf, maxCapacity)
	for sc.Scan() {
		_ = fdb.Set(sc.Bytes(), nil)
	}
	return nil
}

// Reset the db
func (fdb *FileDB) Reset() error {
	if fdb.bm != nil {
		fdb.bm.ClearAll()
	}
	if _, err := fdb.tmpDb.Seek(0, 0); err != nil {
		return err
	}
	if err := fdb.tmpDb.Truncate(0); err != nil {
		return err
	}
	if _, err := fdb.db.Seek(0, 0); err != nil {
		return err
	}
	if err := fdb.db.Truncate(0); err != nil {
		return err
	}

	return nil
}

// Size - returns the size of the database in bytes
func (fdb *FileDB) Size() int64 {
	osstat, err := fdb.db.Stat()
	if err != nil {
		return 0
	}
	return osstat.Size()
}

// Close ...
func (fdb *FileDB) Close() {
	tmpDBFilename := fdb.tmpDb.Name()
	fdb.tmpDb.Close()
	os.RemoveAll(tmpDBFilename)

	fdb.db.Close()
	dbFilename := fdb.db.Name()
	if fdb.options.Cleanup {
		os.RemoveAll(dbFilename)
	}
}

func (fdb *FileDB) set(k, v []byte) error {
	var s strings.Builder
	s.Write(k)
	s.WriteString(Separator)
	s.WriteString(string(v))
	s.WriteString("\n")
	_, err := fdb.db.WriteString(s.String())
	if err != nil {
		return err
	}
	fdb.stats.NumberOfItems++
	return nil
}

func (fdb *FileDB) Set(k, v []byte) error {
	// check for duplicates
	if fdb.options.Dedupe && fdb.bm != nil {
		if !fdb.bm.Test(k) {
			fdb.bm.Add(k)
			return fdb.set(k, v)
		} else {
			fdb.stats.NumberOfDupedItems++
			return errors.New("item already exist")
		}
	}

	fdb.stats.NumberOfItems++
	return fdb.set(k, v)
}

// Scan - iterate over the whole store using the handler function
func (fdb *FileDB) Scan(handler func([]byte, []byte) error) error {
	// open the db and scan
	dbCopy, err := os.Open(fdb.options.Path)
	if err != nil {
		return err
	}
	defer dbCopy.Close()

	sc := bufio.NewScanner(dbCopy)
	maxCapacity := 512 * 1024 * 1024
	buf := make([]byte, maxCapacity)
	sc.Buffer(buf, maxCapacity)
	for sc.Scan() {
		tokens := bytes.SplitN(sc.Bytes(), []byte(Separator), 2)
		var k, v []byte
		if len(tokens) > 0 {
			k = tokens[0]
		}
		if len(tokens) > 1 {
			v = tokens[1]
		}
		if err := handler(k, v); err != nil {
			return err
		}
	}
	return nil
}
