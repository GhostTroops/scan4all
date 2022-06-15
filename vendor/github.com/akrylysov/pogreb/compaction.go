package pogreb

import (
	"sync/atomic"

	"github.com/akrylysov/pogreb/internal/errors"
)

// promoteRecord writes the record to the current segment if the index still points to the record.
// Otherwise it discards the record.
func (db *DB) promoteRecord(rec record) (bool, error) {
	hash := db.hash(rec.key)
	it := db.index.newBucketIterator(db.index.bucketIndex(hash))
	for {
		b, err := it.next()
		if err == ErrIterationDone {
			// Exhausted all buckets and the slot wasn't found.
			// The key was deleted or overwritten. The record is safe to discard.
			return true, nil
		}
		if err != nil {
			return false, err
		}
		for i := 0; i < slotsPerBucket; i++ {
			sl := b.slots[i]

			// No more slots in the bucket.
			if sl.offset == 0 {
				break
			}

			// Slot points to a different record.
			if hash != sl.hash || rec.offset != sl.offset || rec.segmentID != sl.segmentID {
				continue
			}

			// The record is in the index, write it to the current segment.
			segmentID, offset, err := db.datalog.writeRecord(rec.data, rec.rtype) // TODO: batch writes
			if err != nil {
				return false, err
			}

			// Update index.
			b.slots[i].segmentID = segmentID
			b.slots[i].offset = offset
			return false, b.write()
		}
	}
}

// CompactionResult holds the compaction result.
type CompactionResult struct {
	CompactedSegments int
	ReclaimedRecords  int
	ReclaimedBytes    int
}

func (db *DB) compact(sourceSeg *segment) (CompactionResult, error) {
	cr := CompactionResult{}

	db.mu.Lock()
	sourceSeg.meta.Full = true // Prevent writes to the compacted file.
	db.mu.Unlock()

	it, err := newSegmentIterator(sourceSeg)
	if err != nil {
		return cr, err
	}
	// Copy records from sourceSeg to the current segment.
	for {
		err := func() error {
			db.mu.Lock()
			defer db.mu.Unlock()
			rec, err := it.next()
			if err != nil {
				return err
			}
			if rec.rtype == recordTypeDelete {
				cr.ReclaimedRecords++
				cr.ReclaimedBytes += len(rec.data)
				return nil
			}
			reclaimed, err := db.promoteRecord(rec)
			if reclaimed {
				cr.ReclaimedRecords++
				cr.ReclaimedBytes += len(rec.data)
			}
			return err
		}()
		if err == ErrIterationDone {
			break
		}
		if err != nil {
			return cr, err
		}
	}

	db.mu.Lock()
	defer db.mu.Unlock()
	err = db.datalog.removeSegment(sourceSeg)
	return cr, err
}

// pickForCompaction returns segments eligible for compaction.
func (db *DB) pickForCompaction() []*segment {
	segments := db.datalog.segmentsBySequenceID()
	var picked []*segment
	for i := len(segments) - 1; i >= 0; i-- {
		seg := segments[i]

		if uint32(seg.size) < db.opts.compactionMinSegmentSize {
			continue
		}

		fragmentation := float32(seg.meta.DeletedBytes) / float32(seg.size)
		if fragmentation < db.opts.compactionMinFragmentation {
			continue
		}

		if seg.meta.DeleteRecords > 0 {
			// Delete records can be discarded only when older segments contain no put records
			// for the corresponding keys.
			// All segments older than the segment eligible for compaction have to be compacted.
			return append(segments[:i+1], picked...)
		}

		picked = append([]*segment{seg}, picked...)
	}
	return picked
}

// Compact compacts the DB. Deleted and overwritten items are discarded.
// Returns an error if compaction is already in progress.
func (db *DB) Compact() (CompactionResult, error) {
	cr := CompactionResult{}

	// Run only a single compaction at a time.
	if !atomic.CompareAndSwapInt32(&db.compactionRunning, 0, 1) {
		return cr, errBusy
	}
	defer func() {
		atomic.StoreInt32(&db.compactionRunning, 0)
	}()

	db.mu.RLock()
	segments := db.pickForCompaction()
	db.mu.RUnlock()

	for _, seg := range segments {
		segcr, err := db.compact(seg)
		if err != nil {
			return cr, errors.Wrapf(err, "compacting segment %s", seg.name)
		}
		cr.CompactedSegments++
		cr.ReclaimedRecords += segcr.ReclaimedRecords
		cr.ReclaimedBytes += segcr.ReclaimedBytes
	}

	return cr, nil
}
