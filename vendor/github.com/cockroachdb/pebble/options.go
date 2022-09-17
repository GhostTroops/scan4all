// Copyright 2011 The LevelDB-Go and Pebble Authors. All rights reserved. Use
// of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package pebble

import (
	"bytes"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/cockroachdb/pebble/internal/base"
	"github.com/cockroachdb/pebble/internal/cache"
	"github.com/cockroachdb/pebble/internal/humanize"
	"github.com/cockroachdb/pebble/sstable"
	"github.com/cockroachdb/pebble/vfs"
)

const (
	cacheDefaultSize = 8 << 20 // 8 MB
)

// Compression exports the base.Compression type.
type Compression = sstable.Compression

// Exported Compression constants.
const (
	DefaultCompression = sstable.DefaultCompression
	NoCompression      = sstable.NoCompression
	SnappyCompression  = sstable.SnappyCompression
	ZstdCompression    = sstable.ZstdCompression
)

// FilterType exports the base.FilterType type.
type FilterType = base.FilterType

// Exported TableFilter constants.
const (
	TableFilter = base.TableFilter
)

// FilterWriter exports the base.FilterWriter type.
type FilterWriter = base.FilterWriter

// FilterPolicy exports the base.FilterPolicy type.
type FilterPolicy = base.FilterPolicy

// TablePropertyCollector exports the sstable.TablePropertyCollector type.
type TablePropertyCollector = sstable.TablePropertyCollector

// IterOptions hold the optional per-query parameters for NewIter.
//
// Like Options, a nil *IterOptions is valid and means to use the default
// values.
type IterOptions struct {
	// LowerBound specifies the smallest key (inclusive) that the iterator will
	// return during iteration. If the iterator is seeked or iterated past this
	// boundary the iterator will return Valid()==false. Setting LowerBound
	// effectively truncates the key space visible to the iterator.
	LowerBound []byte
	// UpperBound specifies the largest key (exclusive) that the iterator will
	// return during iteration. If the iterator is seeked or iterated past this
	// boundary the iterator will return Valid()==false. Setting UpperBound
	// effectively truncates the key space visible to the iterator.
	UpperBound []byte
	// TableFilter can be used to filter the tables that are scanned during
	// iteration based on the user properties. Return true to scan the table and
	// false to skip scanning. This function must be thread-safe since the same
	// function can be used by multiple iterators, if the iterator is cloned.
	TableFilter func(userProps map[string]string) bool

	// Internal options.
	logger Logger
}

// GetLowerBound returns the LowerBound or nil if the receiver is nil.
func (o *IterOptions) GetLowerBound() []byte {
	if o == nil {
		return nil
	}
	return o.LowerBound
}

// GetUpperBound returns the UpperBound or nil if the receiver is nil.
func (o *IterOptions) GetUpperBound() []byte {
	if o == nil {
		return nil
	}
	return o.UpperBound
}

func (o *IterOptions) getLogger() Logger {
	if o == nil || o.logger == nil {
		return DefaultLogger
	}
	return o.logger
}

// WriteOptions hold the optional per-query parameters for Set and Delete
// operations.
//
// Like Options, a nil *WriteOptions is valid and means to use the default
// values.
type WriteOptions struct {
	// Sync is whether to sync writes through the OS buffer cache and down onto
	// the actual disk, if applicable. Setting Sync is required for durability of
	// individual write operations but can result in slower writes.
	//
	// If false, and the process or machine crashes, then a recent write may be
	// lost. This is due to the recently written data being buffered inside the
	// process running Pebble. This differs from the semantics of a write system
	// call in which the data is buffered in the OS buffer cache and would thus
	// survive a process crash.
	//
	// The default value is true.
	Sync bool
}

// Sync specifies the default write options for writes which synchronize to
// disk.
var Sync = &WriteOptions{Sync: true}

// NoSync specifies the default write options for writes which do not
// synchronize to disk.
var NoSync = &WriteOptions{Sync: false}

// GetSync returns the Sync value or true if the receiver is nil.
func (o *WriteOptions) GetSync() bool {
	return o == nil || o.Sync
}

// LevelOptions holds the optional per-level parameters.
type LevelOptions struct {
	// BlockRestartInterval is the number of keys between restart points
	// for delta encoding of keys.
	//
	// The default value is 16.
	BlockRestartInterval int

	// BlockSize is the target uncompressed size in bytes of each table block.
	//
	// The default value is 4096.
	BlockSize int

	// BlockSizeThreshold finishes a block if the block size is larger than the
	// specified percentage of the target block size and adding the next entry
	// would cause the block to be larger than the target block size.
	//
	// The default value is 90
	BlockSizeThreshold int

	// Compression defines the per-block compression to use.
	//
	// The default value (DefaultCompression) uses snappy compression.
	Compression Compression

	// FilterPolicy defines a filter algorithm (such as a Bloom filter) that can
	// reduce disk reads for Get calls.
	//
	// One such implementation is bloom.FilterPolicy(10) from the pebble/bloom
	// package.
	//
	// The default value means to use no filter.
	FilterPolicy FilterPolicy

	// FilterType defines whether an existing filter policy is applied at a
	// block-level or table-level. Block-level filters use less memory to create,
	// but are slower to access as a check for the key in the index must first be
	// performed to locate the filter block. A table-level filter will require
	// memory proportional to the number of keys in an sstable to create, but
	// avoids the index lookup when determining if a key is present. Table-level
	// filters should be preferred except under constrained memory situations.
	FilterType FilterType

	// IndexBlockSize is the target uncompressed size in bytes of each index
	// block. When the index block size is larger than this target, two-level
	// indexes are automatically enabled. Setting this option to a large value
	// (such as math.MaxInt32) disables the automatic creation of two-level
	// indexes.
	//
	// The default value is the value of BlockSize.
	IndexBlockSize int

	// The target file size for the level.
	TargetFileSize int64
}

// EnsureDefaults ensures that the default values for all of the options have
// been initialized. It is valid to call EnsureDefaults on a nil receiver. A
// non-nil result will always be returned.
func (o *LevelOptions) EnsureDefaults() *LevelOptions {
	if o == nil {
		o = &LevelOptions{}
	}
	if o.BlockRestartInterval <= 0 {
		o.BlockRestartInterval = base.DefaultBlockRestartInterval
	}
	if o.BlockSize <= 0 {
		o.BlockSize = base.DefaultBlockSize
	}
	if o.BlockSizeThreshold <= 0 {
		o.BlockSizeThreshold = base.DefaultBlockSizeThreshold
	}
	if o.Compression <= DefaultCompression || o.Compression >= sstable.NCompression {
		o.Compression = SnappyCompression
	}
	if o.IndexBlockSize <= 0 {
		o.IndexBlockSize = o.BlockSize
	}
	if o.TargetFileSize <= 0 {
		o.TargetFileSize = 2 << 20 // 2 MB
	}
	return o
}

// Options holds the optional parameters for configuring pebble. These options
// apply to the DB at large; per-query options are defined by the IterOptions
// and WriteOptions types.
type Options struct {
	// Sync sstables periodically in order to smooth out writes to disk. This
	// option does not provide any persistency guarantee, but is used to avoid
	// latency spikes if the OS automatically decides to write out a large chunk
	// of dirty filesystem buffers. This option only controls SSTable syncs; WAL
	// syncs are controlled by WALBytesPerSync.
	//
	// The default value is 512KB.
	BytesPerSync int

	// Cache is used to cache uncompressed blocks from sstables.
	//
	// The default cache size is 8 MB.
	Cache *cache.Cache

	// Cleaner cleans obsolete files.
	//
	// The default cleaner uses the DeleteCleaner.
	Cleaner Cleaner

	// Comparer defines a total ordering over the space of []byte keys: a 'less
	// than' relationship. The same comparison algorithm must be used for reads
	// and writes over the lifetime of the DB.
	//
	// The default value uses the same ordering as bytes.Compare.
	Comparer *Comparer

	// DebugCheck is invoked, if non-nil, whenever a new version is being
	// installed. Typically, this is set to pebble.DebugCheckLevels in tests
	// or tools only, to check invariants over all the data in the database.
	DebugCheck func(*DB) error

	// Disable the write-ahead log (WAL). Disabling the write-ahead log prohibits
	// crash recovery, but can improve performance if crash recovery is not
	// needed (e.g. when only temporary state is being stored in the database).
	//
	// TODO(peter): untested
	DisableWAL bool

	// ErrorIfExists is whether it is an error if the database already exists.
	//
	// The default value is false.
	ErrorIfExists bool

	// ErrorIfNotExists is whether it is an error if the database does not
	// already exist.
	//
	// The default value is false which will cause a database to be created if it
	// does not already exist.
	ErrorIfNotExists bool

	// EventListener provides hooks to listening to significant DB events such as
	// flushes, compactions, and table deletion.
	EventListener EventListener

	// Experimental contains experimental options which are off by default.
	// These options are temporary and will eventually either be deleted, moved
	// out of the experimental group, or made the non-adjustable default. These
	// options may change at any time, so do not rely on them.
	Experimental struct {
		// The threshold of L0 read-amplification at which compaction concurrency
		// is enabled (if CompactionDebtConcurrency was not already exceeded).
		// Every multiple of this value enables another concurrent
		// compaction up to MaxConcurrentCompactions.
		L0CompactionConcurrency int

		// CompactionDebtConcurrency controls the threshold of compaction debt
		// at which additional compaction concurrency slots are added. For every
		// multiple of this value in compaction debt bytes, an additional
		// concurrent compaction is added. This works "on top" of
		// L0CompactionConcurrency, so the higher of the count of compaction
		// concurrency slots as determined by the two options is chosen.
		CompactionDebtConcurrency int

		// DeleteRangeFlushDelay configures how long the database should wait
		// before forcing a flush of a memtable that contains a range
		// deletion. Disk space cannot be reclaimed until the range deletion
		// is flushed. No automatic flush occurs if zero.
		DeleteRangeFlushDelay time.Duration

		// MinDeletionRate is the minimum number of bytes per second that would
		// be deleted. Deletion pacing is used to slow down deletions when
		// compactions finish up or readers close, and newly-obsolete files need
		// cleaning up. Deleting lots of files at once can cause disk latency to
		// go up on some SSDs, which this functionality guards against. This is a
		// minimum as the maximum is theoretically unlimited; pacing is disabled
		// when there are too many obsolete files relative to live bytes, or
		// there isn't enough disk space available. Setting this to 0 disables
		// deletion pacing, which is also the default.
		MinDeletionRate int

		// ReadCompactionRate controls the frequency of read triggered
		// compactions by adjusting `AllowedSeeks` in manifest.FileMetadata:
		//
		// AllowedSeeks = FileSize / ReadCompactionRate
		//
		// From LevelDB:
		// ```
		// We arrange to automatically compact this file after
		// a certain number of seeks. Let's assume:
		//   (1) One seek costs 10ms
		//   (2) Writing or reading 1MB costs 10ms (100MB/s)
		//   (3) A compaction of 1MB does 25MB of IO:
		//         1MB read from this level
		//         10-12MB read from next level (boundaries may be misaligned)
		//         10-12MB written to next level
		// This implies that 25 seeks cost the same as the compaction
		// of 1MB of data.  I.e., one seek costs approximately the
		// same as the compaction of 40KB of data.  We are a little
		// conservative and allow approximately one seek for every 16KB
		// of data before triggering a compaction.
		// ```
		ReadCompactionRate int64

		// ReadSamplingMultiplier is a multiplier for the readSamplingPeriod in
		// iterator.maybeSampleRead() to control the frequency of read sampling
		// to trigger a read triggered compaction. A value of -1 prevents sampling
		// and disables read triggered compactions. The default is 1 << 4. which
		// gets multiplied with a constant of 1 << 16 to yield 1 << 20 (1MB).
		ReadSamplingMultiplier int64

		// TableCacheShards is the number of shards per table cache.
		// Reducing the value can reduce the number of idle goroutines per DB
		// instance which can be useful in scenarios with a lot of DB instances
		// and a large number of CPUs, but doing so can lead to higher contention
		// in the table cache and reduced performance.
		//
		// The default value is the number of logical CPUs, which can be
		// limited by runtime.GOMAXPROCS.
		TableCacheShards int
	}

	// Filters is a map from filter policy name to filter policy. It is used for
	// debugging tools which may be used on multiple databases configured with
	// different filter policies. It is not necessary to populate this filters
	// map during normal usage of a DB.
	Filters map[string]FilterPolicy

	// FlushSplitBytes denotes the target number of bytes per sublevel in
	// each flush split interval (i.e. range between two flush split keys)
	// in L0 sstables. When set to zero, only a single sstable is generated
	// by each flush. When set to a non-zero value, flushes are split at
	// points to meet L0's TargetFileSize, any grandparent-related overlap
	// options, and at boundary keys of L0 flush split intervals (which are
	// targeted to contain around FlushSplitBytes bytes in each sublevel
	// between pairs of boundary keys). Splitting sstables during flush
	// allows increased compaction flexibility and concurrency when those
	// tables are compacted to lower levels.
	FlushSplitBytes int64

	// FS provides the interface for persistent file storage.
	//
	// The default value uses the underlying operating system's file system.
	FS vfs.FS

	// The amount of L0 read-amplification necessary to trigger an L0 compaction.
	L0CompactionThreshold int

	// Hard limit on L0 read-amplification. Writes are stopped when this
	// threshold is reached. If Experimental.L0SublevelCompactions is enabled
	// this threshold is measured against the number of L0 sublevels. Otherwise
	// it is measured against the number of files in L0.
	L0StopWritesThreshold int

	// The maximum number of bytes for LBase. The base level is the level which
	// L0 is compacted into. The base level is determined dynamically based on
	// the existing data in the LSM. The maximum number of bytes for other levels
	// is computed dynamically based on the base level's maximum size. When the
	// maximum number of bytes for a level is exceeded, compaction is requested.
	LBaseMaxBytes int64

	// Per-level options. Options for at least one level must be specified. The
	// options for the last level are used for all subsequent levels.
	Levels []LevelOptions

	// Logger used to write log messages.
	//
	// The default logger uses the Go standard library log package.
	Logger Logger

	// MaxManifestFileSize is the maximum size the MANIFEST file is allowed to
	// become. When the MANIFEST exceeds this size it is rolled over and a new
	// MANIFEST is created.
	MaxManifestFileSize int64

	// MaxOpenFiles is a soft limit on the number of open files that can be
	// used by the DB.
	//
	// The default value is 1000.
	MaxOpenFiles int

	// The size of a MemTable in steady state. The actual MemTable size starts at
	// min(256KB, MemTableSize) and doubles for each subsequent MemTable up to
	// MemTableSize. This reduces the memory pressure caused by MemTables for
	// short lived (test) DB instances. Note that more than one MemTable can be
	// in existence since flushing a MemTable involves creating a new one and
	// writing the contents of the old one in the
	// background. MemTableStopWritesThreshold places a hard limit on the size of
	// the queued MemTables.
	MemTableSize int

	// Hard limit on the size of queued of MemTables. Writes are stopped when the
	// sum of the queued memtable sizes exceeds
	// MemTableStopWritesThreshold*MemTableSize. This value should be at least 2
	// or writes will stop whenever a MemTable is being flushed.
	MemTableStopWritesThreshold int

	// Merger defines the associative merge operation to use for merging values
	// written with {Batch,DB}.Merge.
	//
	// The default merger concatenates values.
	Merger *Merger

	// MaxConcurrentCompactions specifies the maximum number of concurrent
	// compactions. The default is 1. Concurrent compactions are only performed
	// when L0 read-amplification passes the L0CompactionConcurrency threshold.
	MaxConcurrentCompactions int

	// ReadOnly indicates that the DB should be opened in read-only mode. Writes
	// to the DB will return an error, background compactions are disabled, and
	// the flush that normally occurs after replaying the WAL at startup is
	// disabled.
	ReadOnly bool

	// TablePropertyCollectors is a list of TablePropertyCollector creation
	// functions. A new TablePropertyCollector is created for each sstable built
	// and lives for the lifetime of the table.
	TablePropertyCollectors []func() TablePropertyCollector

	// WALBytesPerSync sets the number of bytes to write to a WAL before calling
	// Sync on it in the background. Just like with BytesPerSync above, this
	// helps smooth out disk write latencies, and avoids cases where the OS
	// writes a lot of buffered data to disk at once. However, this is less
	// necessary with WALs, as many write operations already pass in
	// Sync = true.
	//
	// The default value is 0, i.e. no background syncing. This matches the
	// default behaviour in RocksDB.
	WALBytesPerSync int

	// WALDir specifies the directory to store write-ahead logs (WALs) in. If
	// empty (the default), WALs will be stored in the same directory as sstables
	// (i.e. the directory passed to pebble.Open).
	WALDir string

	// WALMinSyncInterval is the minimum duration between syncs of the WAL. If
	// WAL syncs are requested faster than this interval, they will be
	// artificially delayed. Introducing a small artificial delay (500us) between
	// WAL syncs can allow more operations to arrive and reduce IO operations
	// while having a minimal impact on throughput. This option is supplied as a
	// closure in order to allow the value to be changed dynamically. The default
	// value is 0.
	//
	// TODO(peter): rather than a closure, should there be another mechanism for
	// changing options dynamically?
	WALMinSyncInterval func() time.Duration

	// private options are only used by internal tests or are used internally
	// for facilitating upgrade paths of unconfigurable functionality.
	private struct {
		// strictWALTail configures whether or not a database's WALs created
		// prior to the most recent one should be interpreted strictly,
		// requiring a clean EOF. RocksDB 6.2.1 and the version of Pebble
		// included in CockroachDB 20.1 do not guarantee that closed WALs end
		// cleanly. If this option is set within an OPTIONS file, Pebble
		// interprets previous WALs strictly, requiring a clean EOF.
		// Otherwise, it interprets them permissively in the same manner as
		// RocksDB 6.2.1.
		strictWALTail bool

		// TODO(peter): A private option to enable flush/compaction pacing. Only used
		// by tests. Compaction/flush pacing is disabled until we fix the impact on
		// throughput.
		enablePacing bool

		// A private option to disable stats collection.
		disableTableStats bool

		// A private option disable automatic compactions.
		disableAutomaticCompactions bool

		// minCompactionRate sets the minimum rate at which compactions occur. The
		// default is 4 MB/s. Currently disabled as this option has no effect while
		// private.enablePacing is false.
		minCompactionRate int

		// minFlushRate sets the minimum rate at which the MemTables are flushed. The
		// default is 1 MB/s. Currently disabled as this option has no effect while
		// private.enablePacing is false.
		minFlushRate int
	}
}

// DebugCheckLevels calls CheckLevels on the provided database.
// It may be set in the DebugCheck field of Options to check
// level invariants whenever a new version is installed.
func DebugCheckLevels(db *DB) error {
	return db.CheckLevels(nil)
}

// EnsureDefaults ensures that the default values for all options are set if a
// valid value was not already specified. Returns the new options.
func (o *Options) EnsureDefaults() *Options {
	if o == nil {
		o = &Options{}
	}
	if o.BytesPerSync <= 0 {
		o.BytesPerSync = 512 << 10 // 512 KB
	}
	if o.Cleaner == nil {
		o.Cleaner = DeleteCleaner{}
	}
	if o.Comparer == nil {
		o.Comparer = DefaultComparer
	}
	if o.Experimental.L0CompactionConcurrency <= 0 {
		o.Experimental.L0CompactionConcurrency = 10
	}
	if o.Experimental.CompactionDebtConcurrency <= 0 {
		o.Experimental.CompactionDebtConcurrency = 1 << 30 // 1 GB
	}
	if o.L0CompactionThreshold <= 0 {
		o.L0CompactionThreshold = 4
	}
	if o.L0StopWritesThreshold <= 0 {
		o.L0StopWritesThreshold = 12
	}
	if o.LBaseMaxBytes <= 0 {
		o.LBaseMaxBytes = 64 << 20 // 64 MB
	}
	if o.Levels == nil {
		o.Levels = make([]LevelOptions, 1)
		for i := range o.Levels {
			if i > 0 {
				l := &o.Levels[i]
				if l.TargetFileSize <= 0 {
					l.TargetFileSize = o.Levels[i-1].TargetFileSize * 2
				}
			}
			o.Levels[i].EnsureDefaults()
		}
	} else {
		for i := range o.Levels {
			o.Levels[i].EnsureDefaults()
		}
	}
	if o.Logger == nil {
		o.Logger = DefaultLogger
	}
	o.EventListener.EnsureDefaults(o.Logger)
	if o.MaxManifestFileSize == 0 {
		o.MaxManifestFileSize = 128 << 20 // 128 MB
	}
	if o.MaxOpenFiles == 0 {
		o.MaxOpenFiles = 1000
	}
	if o.MemTableSize <= 0 {
		o.MemTableSize = 4 << 20
	}
	if o.MemTableStopWritesThreshold <= 0 {
		o.MemTableStopWritesThreshold = 2
	}
	if o.Merger == nil {
		o.Merger = DefaultMerger
	}
	o.private.strictWALTail = true
	if o.private.minCompactionRate == 0 {
		o.private.minCompactionRate = 4 << 20 // 4 MB/s
	}
	if o.private.minFlushRate == 0 {
		o.private.minFlushRate = 1 << 20 // 1 MB/s
	}
	if o.MaxConcurrentCompactions <= 0 {
		o.MaxConcurrentCompactions = 1
	}
	if o.FS == nil {
		o.FS = vfs.WithDiskHealthChecks(vfs.Default, 5*time.Second,
			func(name string, duration time.Duration) {
				o.EventListener.DiskSlow(DiskSlowInfo{
					Path:     name,
					Duration: duration,
				})
			})
	}
	if o.FlushSplitBytes <= 0 {
		o.FlushSplitBytes = 2 * o.Levels[0].TargetFileSize
	}
	if o.Experimental.ReadCompactionRate == 0 {
		o.Experimental.ReadCompactionRate = 16000
	}
	if o.Experimental.ReadSamplingMultiplier == 0 {
		o.Experimental.ReadSamplingMultiplier = 1 << 4
	}
	if o.Experimental.TableCacheShards <= 0 {
		o.Experimental.TableCacheShards = runtime.GOMAXPROCS(0)
	}

	o.initMaps()
	return o
}

// initMaps initializes the Comparers, Filters, and Mergers maps.
func (o *Options) initMaps() {
	for i := range o.Levels {
		l := &o.Levels[i]
		if l.FilterPolicy != nil {
			if o.Filters == nil {
				o.Filters = make(map[string]FilterPolicy)
			}
			name := l.FilterPolicy.Name()
			if _, ok := o.Filters[name]; !ok {
				o.Filters[name] = l.FilterPolicy
			}
		}
	}
}

// Level returns the LevelOptions for the specified level.
func (o *Options) Level(level int) LevelOptions {
	if level < len(o.Levels) {
		return o.Levels[level]
	}
	n := len(o.Levels) - 1
	l := o.Levels[n]
	for i := n; i < level; i++ {
		l.TargetFileSize *= 2
	}
	return l
}

// Clone creates a shallow-copy of the supplied options.
func (o *Options) Clone() *Options {
	n := &Options{}
	if o != nil {
		*n = *o
	}
	return n
}

func filterPolicyName(p FilterPolicy) string {
	if p == nil {
		return "none"
	}
	return p.Name()
}

func (o *Options) String() string {
	var buf bytes.Buffer

	cacheSize := int64(cacheDefaultSize)
	if o.Cache != nil {
		cacheSize = o.Cache.MaxSize()
	}

	fmt.Fprintf(&buf, "[Version]\n")
	fmt.Fprintf(&buf, "  pebble_version=0.1\n")
	fmt.Fprintf(&buf, "\n")
	fmt.Fprintf(&buf, "[Options]\n")
	fmt.Fprintf(&buf, "  bytes_per_sync=%d\n", o.BytesPerSync)
	fmt.Fprintf(&buf, "  cache_size=%d\n", cacheSize)
	fmt.Fprintf(&buf, "  cleaner=%s\n", o.Cleaner)
	fmt.Fprintf(&buf, "  compaction_debt_concurrency=%d\n", o.Experimental.CompactionDebtConcurrency)
	fmt.Fprintf(&buf, "  comparer=%s\n", o.Comparer.Name)
	fmt.Fprintf(&buf, "  delete_range_flush_delay=%s\n", o.Experimental.DeleteRangeFlushDelay)
	fmt.Fprintf(&buf, "  disable_wal=%t\n", o.DisableWAL)
	fmt.Fprintf(&buf, "  flush_split_bytes=%d\n", o.FlushSplitBytes)
	fmt.Fprintf(&buf, "  l0_compaction_concurrency=%d\n", o.Experimental.L0CompactionConcurrency)
	fmt.Fprintf(&buf, "  l0_compaction_threshold=%d\n", o.L0CompactionThreshold)
	fmt.Fprintf(&buf, "  l0_stop_writes_threshold=%d\n", o.L0StopWritesThreshold)
	fmt.Fprintf(&buf, "  lbase_max_bytes=%d\n", o.LBaseMaxBytes)
	fmt.Fprintf(&buf, "  max_concurrent_compactions=%d\n", o.MaxConcurrentCompactions)
	fmt.Fprintf(&buf, "  max_manifest_file_size=%d\n", o.MaxManifestFileSize)
	fmt.Fprintf(&buf, "  max_open_files=%d\n", o.MaxOpenFiles)
	fmt.Fprintf(&buf, "  mem_table_size=%d\n", o.MemTableSize)
	fmt.Fprintf(&buf, "  mem_table_stop_writes_threshold=%d\n", o.MemTableStopWritesThreshold)
	fmt.Fprintf(&buf, "  min_compaction_rate=%d\n", o.private.minCompactionRate)
	fmt.Fprintf(&buf, "  min_deletion_rate=%d\n", o.Experimental.MinDeletionRate)
	fmt.Fprintf(&buf, "  min_flush_rate=%d\n", o.private.minFlushRate)
	fmt.Fprintf(&buf, "  merger=%s\n", o.Merger.Name)
	fmt.Fprintf(&buf, "  read_compaction_rate=%d\n", o.Experimental.ReadCompactionRate)
	fmt.Fprintf(&buf, "  read_sampling_multiplier=%d\n", o.Experimental.ReadSamplingMultiplier)
	fmt.Fprintf(&buf, "  strict_wal_tail=%t\n", o.private.strictWALTail)
	fmt.Fprintf(&buf, "  table_cache_shards=%d\n", o.Experimental.TableCacheShards)
	fmt.Fprintf(&buf, "  table_property_collectors=[")
	for i := range o.TablePropertyCollectors {
		if i > 0 {
			fmt.Fprintf(&buf, ",")
		}
		// NB: This creates a new TablePropertyCollector, but Options.String() is
		// called rarely so the overhead of doing so is not consequential.
		fmt.Fprintf(&buf, "%s", o.TablePropertyCollectors[i]().Name())
	}
	fmt.Fprintf(&buf, "]\n")
	fmt.Fprintf(&buf, "  wal_dir=%s\n", o.WALDir)
	fmt.Fprintf(&buf, "  wal_bytes_per_sync=%d\n", o.WALBytesPerSync)

	for i := range o.Levels {
		l := &o.Levels[i]
		fmt.Fprintf(&buf, "\n")
		fmt.Fprintf(&buf, "[Level \"%d\"]\n", i)
		fmt.Fprintf(&buf, "  block_restart_interval=%d\n", l.BlockRestartInterval)
		fmt.Fprintf(&buf, "  block_size=%d\n", l.BlockSize)
		fmt.Fprintf(&buf, "  compression=%s\n", l.Compression)
		fmt.Fprintf(&buf, "  filter_policy=%s\n", filterPolicyName(l.FilterPolicy))
		fmt.Fprintf(&buf, "  filter_type=%s\n", l.FilterType)
		fmt.Fprintf(&buf, "  index_block_size=%d\n", l.IndexBlockSize)
		fmt.Fprintf(&buf, "  target_file_size=%d\n", l.TargetFileSize)
	}

	return buf.String()
}

func parseOptions(s string, fn func(section, key, value string) error) error {
	var section string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			// Skip blank lines.
			continue
		}
		if line[0] == ';' || line[0] == '#' {
			// Skip comments.
			continue
		}
		n := len(line)
		if line[0] == '[' && line[n-1] == ']' {
			// Parse section.
			section = line[1 : n-1]
			continue
		}

		pos := strings.Index(line, "=")
		if pos < 0 {
			return errors.Errorf("pebble: invalid key=value syntax: %s", errors.Safe(line))
		}

		key := strings.TrimSpace(line[:pos])
		value := strings.TrimSpace(line[pos+1:])

		// RocksDB uses a similar (INI-style) syntax for the OPTIONS file, but
		// different section names and keys. The "CFOptions ..." paths are the
		// RocksDB versions which we map to the Pebble paths.
		mappedSection := section
		if section == `CFOptions "default"` {
			mappedSection = "Options"
			switch key {
			case "comparator":
				key = "comparer"
			case "merge_operator":
				key = "merger"
			}
		}

		if err := fn(mappedSection, key, value); err != nil {
			return err
		}
	}
	return nil
}

// ParseHooks contains callbacks to create options fields which can have
// user-defined implementations.
type ParseHooks struct {
	NewCache        func(size int64) *Cache
	NewCleaner      func(name string) (Cleaner, error)
	NewComparer     func(name string) (*Comparer, error)
	NewFilterPolicy func(name string) (FilterPolicy, error)
	NewMerger       func(name string) (*Merger, error)
	SkipUnknown     func(name string) bool
}

// Parse parses the options from the specified string. Note that certain
// options cannot be parsed into populated fields. For example, comparer and
// merger.
func (o *Options) Parse(s string, hooks *ParseHooks) error {
	return parseOptions(s, func(section, key, value string) error {
		// WARNING: DO NOT remove entries from the switches below because doing so
		// causes a key previously written to the OPTIONS file to be considered unknown,
		// a backwards incompatible change. Instead, leave in support for parsing the
		// key but simply don't parse the value.

		switch {
		case section == "Version":
			switch key {
			case "pebble_version":
			default:
				if hooks != nil && hooks.SkipUnknown != nil && hooks.SkipUnknown(section+"."+key) {
					return nil
				}
				return errors.Errorf("pebble: unknown option: %s.%s",
					errors.Safe(section), errors.Safe(key))
			}
			return nil

		case section == "Options":
			var err error
			switch key {
			case "bytes_per_sync":
				o.BytesPerSync, err = strconv.Atoi(value)
			case "cache_size":
				var n int64
				n, err = strconv.ParseInt(value, 10, 64)
				if err == nil && hooks != nil && hooks.NewCache != nil {
					if o.Cache != nil {
						o.Cache.Unref()
					}
					o.Cache = hooks.NewCache(n)
				}
				// We avoid calling cache.New in parsing because it makes it
				// too easy to leak a cache.
			case "cleaner":
				switch value {
				case "archive":
					o.Cleaner = ArchiveCleaner{}
				case "delete":
					o.Cleaner = DeleteCleaner{}
				default:
					if hooks != nil && hooks.NewCleaner != nil {
						o.Cleaner, err = hooks.NewCleaner(value)
					}
				}
			case "comparer":
				switch value {
				case "leveldb.BytewiseComparator":
					o.Comparer = DefaultComparer
				default:
					if hooks != nil && hooks.NewComparer != nil {
						o.Comparer, err = hooks.NewComparer(value)
					}
				}
			case "compaction_debt_concurrency":
				o.Experimental.CompactionDebtConcurrency, err = strconv.Atoi(value)
			case "delete_range_flush_delay":
				o.Experimental.DeleteRangeFlushDelay, err = time.ParseDuration(value)
			case "disable_wal":
				o.DisableWAL, err = strconv.ParseBool(value)
			case "flush_split_bytes":
				o.FlushSplitBytes, err = strconv.ParseInt(value, 10, 64)
			case "l0_compaction_concurrency":
				o.Experimental.L0CompactionConcurrency, err = strconv.Atoi(value)
			case "l0_compaction_threshold":
				o.L0CompactionThreshold, err = strconv.Atoi(value)
			case "l0_stop_writes_threshold":
				o.L0StopWritesThreshold, err = strconv.Atoi(value)
			case "l0_sublevel_compactions":
				// Do nothing; option existed in older versions of pebble.
			case "lbase_max_bytes":
				o.LBaseMaxBytes, err = strconv.ParseInt(value, 10, 64)
			case "max_concurrent_compactions":
				o.MaxConcurrentCompactions, err = strconv.Atoi(value)
			case "max_manifest_file_size":
				o.MaxManifestFileSize, err = strconv.ParseInt(value, 10, 64)
			case "max_open_files":
				o.MaxOpenFiles, err = strconv.Atoi(value)
			case "mem_table_size":
				o.MemTableSize, err = strconv.Atoi(value)
			case "mem_table_stop_writes_threshold":
				o.MemTableStopWritesThreshold, err = strconv.Atoi(value)
			case "min_compaction_rate":
				o.private.minCompactionRate, err = strconv.Atoi(value)
			case "min_deletion_rate":
				o.Experimental.MinDeletionRate, err = strconv.Atoi(value)
			case "min_flush_rate":
				o.private.minFlushRate, err = strconv.Atoi(value)
			case "strict_wal_tail":
				o.private.strictWALTail, err = strconv.ParseBool(value)
			case "merger":
				switch value {
				case "nullptr":
					o.Merger = nil
				case "pebble.concatenate":
					o.Merger = DefaultMerger
				default:
					if hooks != nil && hooks.NewMerger != nil {
						o.Merger, err = hooks.NewMerger(value)
					}
				}
			case "read_compaction_rate":
				o.Experimental.ReadCompactionRate, err = strconv.ParseInt(value, 10, 64)
			case "read_sampling_multiplier":
				o.Experimental.ReadSamplingMultiplier, err = strconv.ParseInt(value, 10, 64)
			case "table_cache_shards":
				o.Experimental.TableCacheShards, err = strconv.Atoi(value)
			case "table_format":
				switch value {
				case "leveldb":
				case "rocksdbv2":
				default:
					return errors.Errorf("pebble: unknown table format: %q", errors.Safe(value))
				}
			case "table_property_collectors":
				// TODO(peter): set o.TablePropertyCollectors
			case "wal_dir":
				o.WALDir = value
			case "wal_bytes_per_sync":
				o.WALBytesPerSync, err = strconv.Atoi(value)
			default:
				if hooks != nil && hooks.SkipUnknown != nil && hooks.SkipUnknown(section+"."+key) {
					return nil
				}
				return errors.Errorf("pebble: unknown option: %s.%s",
					errors.Safe(section), errors.Safe(key))
			}
			return err

		case strings.HasPrefix(section, "Level "):
			var index int
			if n, err := fmt.Sscanf(section, `Level "%d"`, &index); err != nil {
				return err
			} else if n != 1 {
				if hooks != nil && hooks.SkipUnknown != nil && hooks.SkipUnknown(section) {
					return nil
				}
				return errors.Errorf("pebble: unknown section: %q", errors.Safe(section))
			}

			if len(o.Levels) <= index {
				newLevels := make([]LevelOptions, index+1)
				copy(newLevels, o.Levels)
				o.Levels = newLevels
			}
			l := &o.Levels[index]

			var err error
			switch key {
			case "block_restart_interval":
				l.BlockRestartInterval, err = strconv.Atoi(value)
			case "block_size":
				l.BlockSize, err = strconv.Atoi(value)
			case "compression":
				switch value {
				case "Default":
					l.Compression = DefaultCompression
				case "NoCompression":
					l.Compression = NoCompression
				case "Snappy":
					l.Compression = SnappyCompression
				case "ZSTD":
					l.Compression = ZstdCompression
				default:
					return errors.Errorf("pebble: unknown compression: %q", errors.Safe(value))
				}
			case "filter_policy":
				if hooks != nil && hooks.NewFilterPolicy != nil {
					l.FilterPolicy, err = hooks.NewFilterPolicy(value)
				}
			case "filter_type":
				switch value {
				case "table":
					l.FilterType = TableFilter
				default:
					return errors.Errorf("pebble: unknown filter type: %q", errors.Safe(value))
				}
			case "index_block_size":
				l.IndexBlockSize, err = strconv.Atoi(value)
			case "target_file_size":
				l.TargetFileSize, err = strconv.ParseInt(value, 10, 64)
			default:
				if hooks != nil && hooks.SkipUnknown != nil && hooks.SkipUnknown(section+"."+key) {
					return nil
				}
				return errors.Errorf("pebble: unknown option: %s.%s", errors.Safe(section), errors.Safe(key))
			}
			return err
		}
		if hooks != nil && hooks.SkipUnknown != nil && hooks.SkipUnknown(section+"."+key) {
			return nil
		}
		return errors.Errorf("pebble: unknown section: %q", errors.Safe(section))
	})
}

func (o *Options) checkOptions(s string) (strictWALTail bool, err error) {
	// TODO(jackson): Refactor to avoid awkwardness of the strictWALTail return value.
	return strictWALTail, parseOptions(s, func(section, key, value string) error {
		switch section + "." + key {
		case "Options.comparer":
			if value != o.Comparer.Name {
				return errors.Errorf("pebble: comparer name from file %q != comparer name from options %q",
					errors.Safe(value), errors.Safe(o.Comparer.Name))
			}
		case "Options.merger":
			// RocksDB allows the merge operator to be unspecified, in which case it
			// shows up as "nullptr".
			if value != "nullptr" && value != o.Merger.Name {
				return errors.Errorf("pebble: merger name from file %q != merger name from options %q",
					errors.Safe(value), errors.Safe(o.Merger.Name))
			}
		case "Options.strict_wal_tail":
			strictWALTail, err = strconv.ParseBool(value)
			if err != nil {
				return errors.Errorf("pebble: error parsing strict_wal_tail value %q: %w", value, err)
			}
		}
		return nil
	})
}

// Check verifies the options are compatible with the previous options
// serialized by Options.String(). For example, the Comparer and Merger must be
// the same, or data will not be able to be properly read from the DB.
func (o *Options) Check(s string) error {
	_, err := o.checkOptions(s)
	return err
}

// Validate verifies that the options are mutually consistent. For example,
// L0StopWritesThreshold must be >= L0CompactionThreshold, otherwise a write
// stall would persist indefinitely.
func (o *Options) Validate() error {
	// Note that we can presume Options.EnsureDefaults has been called, so there
	// is no need to check for zero values.

	var buf strings.Builder
	if o.Experimental.L0CompactionConcurrency < 1 {
		fmt.Fprintf(&buf, "L0CompactionConcurrency (%d) must be >= 1\n",
			o.Experimental.L0CompactionConcurrency)
	}
	if o.L0StopWritesThreshold < o.L0CompactionThreshold {
		fmt.Fprintf(&buf, "L0StopWritesThreshold (%d) must be >= L0CompactionThreshold (%d)\n",
			o.L0StopWritesThreshold, o.L0CompactionThreshold)
	}
	if uint64(o.MemTableSize) >= maxMemTableSize {
		fmt.Fprintf(&buf, "MemTableSize (%s) must be < %s\n",
			humanize.Uint64(uint64(o.MemTableSize)), humanize.Uint64(maxMemTableSize))
	}
	if o.MemTableStopWritesThreshold < 2 {
		fmt.Fprintf(&buf, "MemTableStopWritesThreshold (%d) must be >= 2\n",
			o.MemTableStopWritesThreshold)
	}
	if buf.Len() == 0 {
		return nil
	}
	return errors.New(buf.String())
}

// MakeReaderOptions constructs sstable.ReaderOptions from the corresponding
// options in the receiver.
func (o *Options) MakeReaderOptions() sstable.ReaderOptions {
	var readerOpts sstable.ReaderOptions
	if o != nil {
		readerOpts.Cache = o.Cache
		readerOpts.Comparer = o.Comparer
		readerOpts.Filters = o.Filters
		if o.Merger != nil {
			readerOpts.MergerName = o.Merger.Name
		}
	}
	return readerOpts
}

// MakeWriterOptions constructs sstable.WriterOptions for the specified level
// from the corresponding options in the receiver.
func (o *Options) MakeWriterOptions(level int) sstable.WriterOptions {
	var writerOpts sstable.WriterOptions
	if o != nil {
		writerOpts.Cache = o.Cache
		writerOpts.Comparer = o.Comparer
		if o.Merger != nil {
			writerOpts.MergerName = o.Merger.Name
		}
		writerOpts.TableFormat = sstable.TableFormatRocksDBv2
		writerOpts.TablePropertyCollectors = o.TablePropertyCollectors
	}
	levelOpts := o.Level(level)
	writerOpts.BlockRestartInterval = levelOpts.BlockRestartInterval
	writerOpts.BlockSize = levelOpts.BlockSize
	writerOpts.BlockSizeThreshold = levelOpts.BlockSizeThreshold
	writerOpts.Compression = levelOpts.Compression
	writerOpts.FilterPolicy = levelOpts.FilterPolicy
	writerOpts.FilterType = levelOpts.FilterType
	writerOpts.IndexBlockSize = levelOpts.IndexBlockSize
	return writerOpts
}
