// Copyright 2012 The LevelDB-Go and Pebble Authors. All rights reserved. Use
// of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package pebble

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"sort"
	"sync/atomic"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/cockroachdb/errors/oserror"
	"github.com/cockroachdb/pebble/internal/arenaskl"
	"github.com/cockroachdb/pebble/internal/base"
	"github.com/cockroachdb/pebble/internal/cache"
	"github.com/cockroachdb/pebble/internal/invariants"
	"github.com/cockroachdb/pebble/internal/manual"
	"github.com/cockroachdb/pebble/internal/rate"
	"github.com/cockroachdb/pebble/record"
	"github.com/cockroachdb/pebble/vfs"
)

const (
	initialMemTableSize = 256 << 10 // 256 KB

	// The max batch size is limited by the uint32 offsets stored in
	// internal/batchskl.node, DeferredBatchOp, and flushableBatchEntry.
	maxBatchSize = 4 << 30 // 4 GB

	// The max memtable size is limited by the uint32 offsets stored in
	// internal/arenaskl.node, DeferredBatchOp, and flushableBatchEntry.
	maxMemTableSize = 4 << 30 // 4 GB
)

// Open opens a DB whose files live in the given directory.
func Open(dirname string, opts *Options) (db *DB, _ error) {
	// Make a copy of the options so that we don't mutate the passed in options.
	opts = opts.Clone()
	opts = opts.EnsureDefaults()
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	if opts.Cache == nil {
		opts.Cache = cache.New(cacheDefaultSize)
	} else {
		opts.Cache.Ref()
	}

	d := &DB{
		cacheID:             opts.Cache.NewID(),
		dirname:             dirname,
		walDirname:          opts.WALDir,
		opts:                opts,
		cmp:                 opts.Comparer.Compare,
		equal:               opts.Comparer.Equal,
		merge:               opts.Merger.Merge,
		split:               opts.Comparer.Split,
		abbreviatedKey:      opts.Comparer.AbbreviatedKey,
		largeBatchThreshold: (opts.MemTableSize - int(memTableEmptySize)) / 2,
		logRecycler:         logRecycler{limit: opts.MemTableStopWritesThreshold + 1},
		closed:              new(atomic.Value),
		closedCh:            make(chan struct{}),
	}
	d.mu.versions = &versionSet{}

	defer func() {
		// If an error or panic occurs during open, attempt to release the manually
		// allocated memory resources. Note that rather than look for an error, we
		// look for the return of a nil DB pointer.
		if r := recover(); db == nil {
			// Release our references to the Cache. Note that both the DB, and
			// tableCache have a reference. The tableCache.Close will release
			// the tableCache's reference.
			opts.Cache.Unref()
			_ = d.tableCache.Close()
			for _, mem := range d.mu.mem.queue {
				switch t := mem.flushable.(type) {
				case *memTable:
					manual.Free(t.arenaBuf)
					t.arenaBuf = nil
				}
			}
			if r != nil {
				panic(r)
			}
		}
	}()

	if d.equal == nil {
		d.equal = bytes.Equal
	}
	tableCacheSize := opts.MaxOpenFiles - numNonTableCacheFiles
	if tableCacheSize < minTableCacheSize {
		tableCacheSize = minTableCacheSize
	}
	d.tableCache.init(d.cacheID, dirname, opts.FS, d.opts, tableCacheSize)
	d.newIters = d.tableCache.newIters
	d.commit = newCommitPipeline(commitEnv{
		logSeqNum:     &d.mu.versions.atomic.logSeqNum,
		visibleSeqNum: &d.mu.versions.atomic.visibleSeqNum,
		apply:         d.commitApply,
		write:         d.commitWrite,
	})
	d.compactionLimiter = rate.NewLimiter(
		rate.Limit(d.opts.private.minCompactionRate),
		d.opts.private.minCompactionRate)
	d.flushLimiter = rate.NewLimiter(
		rate.Limit(d.opts.private.minFlushRate),
		d.opts.private.minFlushRate)
	d.deletionLimiter = rate.NewLimiter(
		rate.Limit(d.opts.Experimental.MinDeletionRate),
		d.opts.Experimental.MinDeletionRate)
	d.mu.nextJobID = 1
	d.mu.mem.nextSize = opts.MemTableSize
	if d.mu.mem.nextSize > initialMemTableSize {
		d.mu.mem.nextSize = initialMemTableSize
	}
	d.mu.mem.cond.L = &d.mu.Mutex
	d.mu.cleaner.cond.L = &d.mu.Mutex
	d.mu.compact.cond.L = &d.mu.Mutex
	d.mu.compact.inProgress = make(map[*compaction]struct{})
	d.mu.snapshots.init()
	// logSeqNum is the next sequence number that will be assigned. Start
	// assigning sequence numbers from 1 to match rocksdb.
	d.mu.versions.atomic.logSeqNum = 1

	d.timeNow = time.Now

	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.opts.ReadOnly {
		err := opts.FS.MkdirAll(dirname, 0755)
		if err != nil {
			return nil, err
		}
	}

	// Open the database and WAL directories first in order to check for their
	// existence.
	var err error
	d.dataDir, err = opts.FS.OpenDir(dirname)
	if err != nil {
		return nil, err
	}
	if d.walDirname == "" {
		d.walDirname = d.dirname
	}
	if d.walDirname == d.dirname {
		d.walDir = d.dataDir
	} else {
		if !d.opts.ReadOnly {
			err := opts.FS.MkdirAll(d.walDirname, 0755)
			if err != nil {
				return nil, err
			}
		}
		d.walDir, err = opts.FS.OpenDir(d.walDirname)
		if err != nil {
			return nil, err
		}
	}

	// Lock the database directory.
	fileLock, err := opts.FS.Lock(base.MakeFilename(opts.FS, dirname, fileTypeLock, 0))
	if err != nil {
		d.dataDir.Close()
		if d.dataDir != d.walDir {
			d.walDir.Close()
		}
		return nil, err
	}
	defer func() {
		if fileLock != nil {
			fileLock.Close()
		}
	}()

	jobID := d.mu.nextJobID
	d.mu.nextJobID++

	currentName := base.MakeFilename(opts.FS, dirname, fileTypeCurrent, 0)
	if _, err := opts.FS.Stat(currentName); oserror.IsNotExist(err) &&
		!d.opts.ReadOnly && !d.opts.ErrorIfNotExists {
		// Create the DB if it did not already exist.
		if err := d.mu.versions.create(jobID, dirname, d.dataDir, opts, &d.mu.Mutex); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, errors.Wrapf(err, "pebble: database %q", dirname)
	} else if opts.ErrorIfExists {
		return nil, errors.Errorf("pebble: database %q already exists", dirname)
	} else {
		// Load the version set.
		if err := d.mu.versions.load(dirname, opts, &d.mu.Mutex); err != nil {
			return nil, err
		}
		if err := d.mu.versions.currentVersion().CheckConsistency(dirname, opts.FS); err != nil {
			return nil, err
		}
	}

	// In read-only mode, we replay directly into the mutable memtable but never
	// flush it. We need to delay creation of the memtable until we know the
	// sequence number of the first batch that will be inserted.
	if !d.opts.ReadOnly {
		var entry *flushableEntry
		d.mu.mem.mutable, entry = d.newMemTable(0 /* logNum */, d.mu.versions.atomic.logSeqNum)
		d.mu.mem.queue = append(d.mu.mem.queue, entry)
	}

	ls, err := opts.FS.List(d.walDirname)
	if err != nil {
		return nil, err
	}
	if d.dirname != d.walDirname {
		ls2, err := opts.FS.List(d.dirname)
		if err != nil {
			return nil, err
		}
		ls = append(ls, ls2...)
	}

	// Replay any newer log files than the ones named in the manifest.
	type fileNumAndName struct {
		num  FileNum
		name string
	}
	var logFiles []fileNumAndName
	var strictWALTail bool
	for _, filename := range ls {
		ft, fn, ok := base.ParseFilename(opts.FS, filename)
		if !ok {
			continue
		}

		// Don't reuse any obsolete file numbers to avoid modifying an
		// ingested sstable's original external file.
		if d.mu.versions.nextFileNum <= fn {
			d.mu.versions.nextFileNum = fn + 1
		}

		switch ft {
		case fileTypeLog:
			if fn >= d.mu.versions.minUnflushedLogNum {
				logFiles = append(logFiles, fileNumAndName{fn, filename})
			}
			if d.logRecycler.minRecycleLogNum <= fn {
				d.logRecycler.minRecycleLogNum = fn + 1
			}
		case fileTypeOptions:
			strictWALTail, err = checkOptions(opts, opts.FS.PathJoin(dirname, filename))
			if err != nil {
				return nil, err
			}
		case fileTypeTemp:
			if !d.opts.ReadOnly {
				// A temp file is leftover if a process exits in the middle of
				// updating the CURRENT file. Remove it.
				err := opts.FS.Remove(opts.FS.PathJoin(dirname, filename))
				if err != nil {
					return nil, err
				}
			}
		}
	}
	sort.Slice(logFiles, func(i, j int) bool {
		return logFiles[i].num < logFiles[j].num
	})

	var ve versionEdit
	for i, lf := range logFiles {
		lastWAL := i == len(logFiles)-1
		maxSeqNum, err := d.replayWAL(jobID, &ve, opts.FS,
			opts.FS.PathJoin(d.walDirname, lf.name), lf.num, strictWALTail && !lastWAL)
		if err != nil {
			return nil, err
		}
		d.mu.versions.markFileNumUsed(lf.num)
		if d.mu.versions.atomic.logSeqNum < maxSeqNum {
			d.mu.versions.atomic.logSeqNum = maxSeqNum
		}
	}
	d.mu.versions.atomic.visibleSeqNum = d.mu.versions.atomic.logSeqNum

	if !d.opts.ReadOnly {
		// Create an empty .log file.
		newLogNum := d.mu.versions.getNextFileNum()
		newLogName := base.MakeFilename(opts.FS, d.walDirname, fileTypeLog, newLogNum)
		d.mu.log.queue = append(d.mu.log.queue, fileInfo{fileNum: newLogNum, fileSize: 0})
		logFile, err := opts.FS.Create(newLogName)
		if err != nil {
			return nil, err
		}
		if err := d.walDir.Sync(); err != nil {
			return nil, err
		}
		d.opts.EventListener.WALCreated(WALCreateInfo{
			JobID:   jobID,
			Path:    newLogName,
			FileNum: newLogNum,
		})
		// This isn't strictly necessary as we don't use the log number for
		// memtables being flushed, only for the next unflushed memtable.
		d.mu.mem.queue[len(d.mu.mem.queue)-1].logNum = newLogNum

		logFile = vfs.NewSyncingFile(logFile, vfs.SyncingFileOptions{
			BytesPerSync:    d.opts.WALBytesPerSync,
			PreallocateSize: d.walPreallocateSize(),
		})
		d.mu.log.LogWriter = record.NewLogWriter(logFile, newLogNum)
		d.mu.log.LogWriter.SetMinSyncInterval(d.opts.WALMinSyncInterval)
		d.mu.versions.metrics.WAL.Files++

		// This logic is slightly different than RocksDB's. Specifically, RocksDB
		// sets MinUnflushedLogNum to max-recovered-log-num + 1. We set it to the
		// newLogNum. There should be no difference in using either value.
		ve.MinUnflushedLogNum = newLogNum
		d.mu.versions.logLock()
		if err := d.mu.versions.logAndApply(jobID, &ve, newFileMetrics(ve.NewFiles), d.dataDir, func() []compactionInfo {
			return nil
		}); err != nil {
			return nil, err
		}
	}
	d.updateReadStateLocked(d.opts.DebugCheck)

	if !d.opts.ReadOnly {
		// Write the current options to disk.
		d.optionsFileNum = d.mu.versions.getNextFileNum()
		optionsFile, err := opts.FS.Create(
			base.MakeFilename(opts.FS, dirname, fileTypeOptions, d.optionsFileNum))
		if err != nil {
			return nil, err
		}
		serializedOpts := []byte(opts.String())
		if _, err := optionsFile.Write(serializedOpts); err != nil {
			return nil, err
		}
		d.optionsFileSize = uint64(len(serializedOpts))
		_ = optionsFile.Sync()
		_ = optionsFile.Close()
		if err := d.dataDir.Sync(); err != nil {
			return nil, err
		}
	}

	if !d.opts.ReadOnly {
		d.scanObsoleteFiles(ls)
		d.deleteObsoleteFiles(jobID, true /* waitForOngoing */)
	} else {
		// All the log files are obsolete.
		d.mu.versions.metrics.WAL.Files = int64(len(logFiles))
	}
	d.mu.tableStats.cond.L = &d.mu.Mutex
	if !d.opts.ReadOnly && !d.opts.private.disableTableStats {
		d.maybeCollectTableStats()
	}
	d.maybeScheduleFlush()
	d.maybeScheduleCompaction()

	// Note: this is a no-op if invariants are disabled or race is enabled.
	//
	// Setting a finalizer on *DB causes *DB to never be reclaimed and the
	// finalizer to never be run. The problem is due to this limitation of
	// finalizers mention in the SetFinalizer docs:
	//
	//   If a cyclic structure includes a block with a finalizer, that cycle is
	//   not guaranteed to be garbage collected and the finalizer is not
	//   guaranteed to run, because there is no ordering that respects the
	//   dependencies.
	//
	// DB has cycles with several of its internal structures: readState,
	// newIters, tableCache, versions, etc. Each of this individually cause a
	// cycle and prevent the finalizer from being run. But we can workaround this
	// finializer limitation by setting a finalizer on another object that is
	// tied to the lifetime of DB: the DB.closed atomic.Value.
	dPtr := fmt.Sprintf("%p", d)
	invariants.SetFinalizer(d.closed, func(obj interface{}) {
		v := obj.(*atomic.Value)
		if err := v.Load(); err == nil {
			fmt.Fprintf(os.Stderr, "%s: unreferenced DB not closed\n", dPtr)
			os.Exit(1)
		}
	})

	d.fileLock, fileLock = fileLock, nil
	return d, nil
}

// GetVersion returns the engine version string from the latest options
// file present in dir. Used to check what Pebble or RocksDB version was last
// used to write to the database stored in this directory. An empty string is
// returned if no valid OPTIONS file with a version key was found.
func GetVersion(dir string, fs vfs.FS) (string, error) {
	ls, err := fs.List(dir)
	if err != nil {
		return "", err
	}
	var version string
	lastOptionsSeen := FileNum(0)
	for _, filename := range ls {
		ft, fn, ok := base.ParseFilename(fs, filename)
		if !ok {
			continue
		}
		switch ft {
		case fileTypeOptions:
			// If this file has a higher number than the last options file
			// processed, reset version. This is because rocksdb often
			// writes multiple options files without deleting previous ones.
			// Otherwise, skip parsing this options file.
			if fn > lastOptionsSeen {
				version = ""
				lastOptionsSeen = fn
			} else {
				continue
			}
			f, err := fs.Open(fs.PathJoin(dir, filename))
			if err != nil {
				return "", err
			}
			data, err := ioutil.ReadAll(f)
			f.Close()

			if err != nil {
				return "", err
			}
			err = parseOptions(string(data), func(section, key, value string) error {
				switch {
				case section == "Version":
					switch key {
					case "pebble_version":
						version = value
					case "rocksdb_version":
						version = fmt.Sprintf("rocksdb v%s", value)
					}
				}
				return nil
			})
			if err != nil {
				return "", err
			}
		}
	}
	return version, nil
}

// replayWAL replays the edits in the specified log file.
//
// d.mu must be held when calling this, but the mutex may be dropped and
// re-acquired during the course of this method.
func (d *DB) replayWAL(
	jobID int, ve *versionEdit, fs vfs.FS, filename string, logNum FileNum, strictWALTail bool,
) (maxSeqNum uint64, err error) {
	file, err := fs.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	var (
		b               Batch
		buf             bytes.Buffer
		mem             *memTable
		entry           *flushableEntry
		toFlush         flushableList
		rr              = record.NewReader(file, logNum)
		offset          int64 // byte offset in rr
		lastFlushOffset int64
	)

	if d.opts.ReadOnly {
		// In read-only mode, we replay directly into the mutable memtable which will
		// never be flushed.
		mem = d.mu.mem.mutable
		if mem != nil {
			entry = d.mu.mem.queue[len(d.mu.mem.queue)-1]
		}
	}

	// Flushes the current memtable, if not nil.
	flushMem := func() {
		if mem == nil {
			return
		}
		var logSize uint64
		if offset >= lastFlushOffset {
			logSize = uint64(offset - lastFlushOffset)
		}
		// Else, this was the initial memtable in the read-only case which must have
		// been empty, but we need to flush it since we don't want to add to it later.
		lastFlushOffset = offset
		entry.logSize = logSize
		if !d.opts.ReadOnly {
			toFlush = append(toFlush, entry)
		}
		mem, entry = nil, nil
	}
	// Creates a new memtable if there is no current memtable.
	ensureMem := func(seqNum uint64) {
		if mem != nil {
			return
		}
		mem, entry = d.newMemTable(logNum, seqNum)
		if d.opts.ReadOnly {
			d.mu.mem.mutable = mem
			d.mu.mem.queue = append(d.mu.mem.queue, entry)
		}
	}
	for {
		offset = rr.Offset()
		r, err := rr.Next()
		if err == nil {
			_, err = io.Copy(&buf, r)
		}
		if err != nil {
			// It is common to encounter a zeroed or invalid chunk due to WAL
			// preallocation and WAL recycling. We need to distinguish these
			// errors from EOF in order to recognize that the record was
			// truncated and to avoid replaying subsequent WALs, but want
			// to otherwise treat them like EOF.
			if err == io.EOF {
				break
			} else if record.IsInvalidRecord(err) && !strictWALTail {
				break
			}
			return 0, errors.Wrap(err, "pebble: error when replaying WAL")
		}

		if buf.Len() < batchHeaderLen {
			return 0, base.CorruptionErrorf("pebble: corrupt log file %q (num %s)",
				filename, errors.Safe(logNum))
		}

		// Specify Batch.db so that Batch.SetRepr will compute Batch.memTableSize
		// which is used below.
		b = Batch{db: d}
		b.SetRepr(buf.Bytes())
		seqNum := b.SeqNum()
		maxSeqNum = seqNum + uint64(b.Count())

		if b.memTableSize >= uint64(d.largeBatchThreshold) {
			flushMem()
			// Make a copy of the data slice since it is currently owned by buf and will
			// be reused in the next iteration.
			b.data = append([]byte(nil), b.data...)
			b.flushable = newFlushableBatch(&b, d.opts.Comparer)
			entry := d.newFlushableEntry(b.flushable, logNum, b.SeqNum())
			// Disable memory accounting by adding a reader ref that will never be
			// removed.
			entry.readerRefs++
			if d.opts.ReadOnly {
				d.mu.mem.queue = append(d.mu.mem.queue, entry)
			} else {
				toFlush = append(toFlush, entry)
			}
		} else {
			ensureMem(seqNum)
			if err = mem.prepare(&b); err != nil && err != arenaskl.ErrArenaFull {
				return 0, err
			}
			// We loop since DB.newMemTable() slowly grows the size of allocated memtables, so the
			// batch may not initially fit, but will eventually fit (since it is smaller than
			// largeBatchThreshold).
			for err == arenaskl.ErrArenaFull {
				flushMem()
				ensureMem(seqNum)
				err = mem.prepare(&b)
				if err != nil && err != arenaskl.ErrArenaFull {
					return 0, err
				}
			}
			if err = mem.apply(&b, seqNum); err != nil {
				return 0, err
			}
			mem.writerUnref()
		}
		buf.Reset()
	}
	flushMem()
	// mem is nil here.
	if !d.opts.ReadOnly {
		c := newFlush(d.opts, d.mu.versions.currentVersion(),
			1 /* base level */, toFlush, &d.atomic.bytesFlushed)
		newVE, _, err := d.runCompaction(jobID, c, nilPacer)
		if err != nil {
			return 0, err
		}
		ve.NewFiles = append(ve.NewFiles, newVE.NewFiles...)
		for i := range toFlush {
			toFlush[i].readerUnref()
		}
	}
	return maxSeqNum, err
}

func checkOptions(opts *Options, path string) (strictWALTail bool, err error) {
	f, err := opts.FS.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	data, err := ioutil.ReadAll(f)
	if err != nil {
		return false, err
	}
	return opts.checkOptions(string(data))
}
