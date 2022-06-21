package pogreb

import (
	"io"
	"path/filepath"

	"github.com/akrylysov/pogreb/fs"
)

const (
	recoveryBackupExt = ".bac"
)

func backupNonsegmentFiles(fsys fs.FileSystem) error {
	logger.Println("moving non-segment files...")

	files, err := fsys.ReadDir(".")
	if err != nil {
		return err
	}

	for _, file := range files {
		name := file.Name()
		ext := filepath.Ext(name)
		if ext == segmentExt || name == lockName {
			continue
		}
		dst := name + recoveryBackupExt
		if err := fsys.Rename(name, dst); err != nil {
			return err
		}
		logger.Printf("moved %s to %s", name, dst)
	}

	return nil
}

func removeRecoveryBackupFiles(fsys fs.FileSystem) error {
	logger.Println("removing recovery backup files...")

	files, err := fsys.ReadDir(".")
	if err != nil {
		return err
	}

	for _, file := range files {
		name := file.Name()
		ext := filepath.Ext(name)
		if ext != recoveryBackupExt {
			continue
		}
		if err := fsys.Remove(name); err != nil {
			return err
		}
		logger.Printf("removed %s", name)
	}

	return nil
}

// recoveryIterator iterates over records of all datalog segments in insertion order.
// Corrupted segments are truncated to the last valid record.
type recoveryIterator struct {
	segments []*segment
	segit    *segmentIterator
}

func newRecoveryIterator(segments []*segment) *recoveryIterator {
	return &recoveryIterator{
		segments: segments,
	}
}

func (it *recoveryIterator) next() (record, error) {
	for {
		if it.segit == nil {
			if len(it.segments) == 0 {
				return record{}, ErrIterationDone
			}
			var err error
			it.segit, err = newSegmentIterator(it.segments[0])
			if err != nil {
				return record{}, err
			}
			it.segments = it.segments[1:]
		}
		rec, err := it.segit.next()
		if err == io.EOF || err == io.ErrUnexpectedEOF || err == errCorrupted {
			// Truncate file to the last valid offset.
			if err := it.segit.f.Truncate(int64(it.segit.offset)); err != nil {
				return record{}, err
			}
			fi, fierr := it.segit.f.Stat()
			if fierr != nil {
				return record{}, fierr
			}
			logger.Printf("truncated segment %s to offset %d", fi.Name(), it.segit.offset)
			err = ErrIterationDone
		}
		if err == ErrIterationDone {
			it.segit = nil
			continue
		}
		if err != nil {
			return record{}, err
		}
		return rec, nil
	}
}

func (db *DB) recover() error {
	logger.Println("started recovery")
	logger.Println("rebuilding index...")

	segments := db.datalog.segmentsBySequenceID()
	it := newRecoveryIterator(segments)
	for {
		rec, err := it.next()
		if err == ErrIterationDone {
			break
		}
		if err != nil {
			return err
		}

		h := db.hash(rec.key)
		meta := db.datalog.segments[rec.segmentID].meta
		if rec.rtype == recordTypePut {
			sl := slot{
				hash:      h,
				segmentID: rec.segmentID,
				keySize:   uint16(len(rec.key)),
				valueSize: uint32(len(rec.value)),
				offset:    rec.offset,
			}
			if err := db.put(sl, rec.key); err != nil {
				return err
			}
			meta.PutRecords++
		} else {
			if err := db.del(h, rec.key, false); err != nil {
				return err
			}
			meta.DeleteRecords++
			meta.DeletedBytes += uint32(len(rec.data))
		}
	}

	// Mark all segments except the newest as full.
	for i := 0; i < len(segments)-1; i++ {
		segments[i].meta.Full = true
	}

	if err := removeRecoveryBackupFiles(db.opts.FileSystem); err != nil {
		logger.Printf("error removing recovery backups files: %v", err)
	}

	logger.Println("successfully recovered database")

	return nil
}
