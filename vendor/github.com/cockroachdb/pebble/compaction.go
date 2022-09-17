// Copyright 2013 The LevelDB-Go and Pebble Authors. All rights reserved. Use
// of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package pebble

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"runtime/pprof"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/cockroachdb/errors/oserror"
	"github.com/cockroachdb/pebble/internal/base"
	"github.com/cockroachdb/pebble/internal/manifest"
	"github.com/cockroachdb/pebble/internal/private"
	"github.com/cockroachdb/pebble/internal/rangedel"
	"github.com/cockroachdb/pebble/sstable"
	"github.com/cockroachdb/pebble/vfs"
)

var errEmptyTable = errors.New("pebble: empty table")
var errFlushInvariant = errors.New("pebble: flush next log number is unset")

var compactLabels = pprof.Labels("pebble", "compact")
var flushLabels = pprof.Labels("pebble", "flush")
var gcLabels = pprof.Labels("pebble", "gc")

// expandedCompactionByteSizeLimit is the maximum number of bytes in all
// compacted files. We avoid expanding the lower level file set of a compaction
// if it would make the total compaction cover more than this many bytes.
func expandedCompactionByteSizeLimit(opts *Options, level int) uint64 {
	return uint64(25 * opts.Level(level).TargetFileSize)
}

// maxGrandparentOverlapBytes is the maximum bytes of overlap with level+1
// before we stop building a single file in a level-1 to level compaction.
func maxGrandparentOverlapBytes(opts *Options, level int) uint64 {
	return uint64(10 * opts.Level(level).TargetFileSize)
}

// noCloseIter wraps around an internal iterator, intercepting and eliding
// calls to Close. It is used during compaction to ensure that rangeDelIters
// are not closed prematurely.
type noCloseIter struct {
	base.InternalIterator
}

func (i noCloseIter) Close() error {
	return nil
}

type compactionLevel struct {
	level int
	files manifest.LevelSlice
}

// Return output from compactionOutputSplitters. See comment on
// compactionOutputSplitter.shouldSplitBefore() on how this value is used.
type compactionSplitSuggestion int

const (
	noSplit compactionSplitSuggestion = iota
	splitNow
)

// String implements the Stringer interface.
func (c compactionSplitSuggestion) String() string {
	if c == noSplit {
		return "no-split"
	}
	return "split-now"
}

// compactionOutputSplitter is an interface for encapsulating logic around
// switching the output of a compaction to a new output file. Additional
// constraints around switching compaction outputs that are specific to that
// compaction type (eg. flush splits) are implemented in
// compactionOutputSplitters that compose other child compactionOutputSplitters.
type compactionOutputSplitter interface {
	// shouldSplitBefore returns whether we should split outputs before the
	// specified "current key". The return value is splitNow or noSplit.
	// splitNow means a split is advised before the specified key, and noSplit
	// means no split is advised.
	shouldSplitBefore(key *InternalKey, tw *sstable.Writer) compactionSplitSuggestion
	// onNewOutput updates internal splitter state when the compaction switches
	// to a new sstable, and returns the next limit for the new output which
	// would get used to truncate range tombstones if the compaction iterator
	// runs out of keys. The limit returned MUST be > key according to the
	// compaction's comparator. The specified key is the first key in the new
	// output, or nil if this sstable will only contain range tombstones already
	// in the fragmenter.
	onNewOutput(key *InternalKey) []byte
}

// fileSizeSplitter is a compactionOutputSplitter that makes a determination
// to split outputs based on the estimated file size of the current output.
// Note that, unlike most other splitters, this splitter does not guarantee
// that it will advise splits only at user key change boundaries.
type fileSizeSplitter struct {
	maxFileSize uint64
}

func (f *fileSizeSplitter) shouldSplitBefore(
	key *InternalKey, tw *sstable.Writer,
) compactionSplitSuggestion {
	// The Kind != RangeDelete part exists because EstimatedSize doesn't grow
	// rightaway when a range tombstone is added to the fragmenter. It's always
	// better to make a sequence of range tombstones visible to the fragmenter.
	if key.Kind() != InternalKeyKindRangeDelete && tw != nil &&
		tw.EstimatedSize() >= f.maxFileSize {
		return splitNow
	}
	return noSplit
}

func (f *fileSizeSplitter) onNewOutput(key *InternalKey) []byte {
	return nil
}

type grandparentLimitSplitter struct {
	c     *compaction
	ve    *versionEdit
	limit []byte
}

func (g *grandparentLimitSplitter) shouldSplitBefore(
	key *InternalKey, tw *sstable.Writer,
) compactionSplitSuggestion {
	if g.limit != nil && g.c.cmp(key.UserKey, g.limit) > 0 {
		return splitNow
	}
	return noSplit
}

func (g *grandparentLimitSplitter) onNewOutput(key *InternalKey) []byte {
	g.limit = nil
	if g.c.rangeDelFrag.Empty() || len(g.ve.NewFiles) == 0 {
		// In this case, `limit` will be a larger user key than `key.UserKey`, or
		// nil. In either case, the inner loop will execute at least once to
		// process `key`, and the input iterator will be advanced.
		if key != nil {
			g.limit = g.c.findGrandparentLimit(key.UserKey)
		} else { // !c.rangeDelFrag.Empty()
			g.limit = g.c.findGrandparentLimit(g.c.rangeDelFrag.Start())
		}
	} else {
		// There is a range tombstone spanning from the last file into the
		// current one. Therefore this file's smallest boundary will overlap the
		// last file's largest boundary.
		//
		// In this case, `limit` will be a larger user key than the previous
		// file's largest key and correspond to a grandparent file's largest user
		// key, or nil. Then, it is possible the inner loop executes zero times,
		// and the output file contains only range tombstones. That is fine as
		// long as the number of times we execute this case is bounded. Since
		// `findGrandparentLimit()` returns a strictly larger user key each time
		// and it corresponds to a grandparent file largest key, the number of
		// times this case can execute is bounded by the number of grandparent
		// files (plus one for the final time it returns nil).
		//
		// n > 0 since we cannot have seen range tombstones at the
		// beginning of the first file.
		n := len(g.ve.NewFiles)
		g.limit = g.c.findGrandparentLimit(g.ve.NewFiles[n-1].Meta.Largest.UserKey)
		// This conditional is necessary to maintain the invariant that
		// successive calls to finishOutput() have an increasing
		// limit, and that the fragmenter's *FlushTo() and Add() calls are
		// always made with successively increasing user keys. It's possible
		// for the last file's Meta.Largest.UserKey
		// to be substantially less than the last key returned by
		// the compactionIter, such as in a sequence of consecutive
		// rangedel tombstones, of which some but not all get elided.
		// Consider this example:
		//
		// Compaction input (all range tombstones in this snippet):
		// a-b
		// c-d
		// e-f  (elided)
		// g-h  (elided) <-- grandparent limit before this (at ff)
		// i-j  (elided)
		// k-q           <-- grandparent limit at k
		// m-q
		//
		// Note that elided tombstones are added to the fragmenter, but
		// removed before they make their way from the fragmenter onto
		// iter.tombstones. They still affect the fragmenter's internal
		// tracking of the key up to which all tombstones have been flushed.
		// After the first output is cut with limit = g, the fragmenter
		// is empty, so the next grandparent calculation happens with
		// key = g, and returns k. We continue adding range tombstones to
		// the fragmenter between [g,k], which includes k-q as we only
		// switch outputs after the limit is exceeded. So key = m and
		// limit = k when finishOutput is called. Since the start key in
		// the fragmenter (k) matches the limit, and no point keys were
		// added, we actually don't produce a new output (see the
		// conditional in finishOutput() on why).
		//
		// When we try to calculate the next grandparent limit, since
		// c.rangeDelFrag.Empty() == false (as k-q is sitting in it),
		// we fall into this case, and use the end key of the last written
		// sstable (which was [a-d]) to calculate the grandparent limit.
		// That gets us g again, which gets us to call
		// c.rangeDelFrag.FlushTo(g), which violates the
		// invariant that the current flush-to key (g) be greater than the
		// last one (k).
		//
		// To solve this, if the grandparent limit falls "in between"
		// ve.NewFiles[n-1].Meta.Largest.UserKey and c.rangeDelFrag.Start(),
		// re-calculate a higher limit ahead of that key.
		if g.c.rangeDelFrag.Start() != nil && g.c.cmp(g.limit, g.c.rangeDelFrag.Start()) <= 0 {
			g.limit = g.c.findGrandparentLimit(g.c.rangeDelFrag.Start())
		}
	}
	return g.limit
}

type l0LimitSplitter struct {
	c     *compaction
	ve    *versionEdit
	limit []byte
}

func (l *l0LimitSplitter) shouldSplitBefore(
	key *InternalKey, tw *sstable.Writer,
) compactionSplitSuggestion {
	if l.limit != nil && l.c.cmp(key.UserKey, l.limit) > 0 {
		return splitNow
	}
	return noSplit
}

func (l *l0LimitSplitter) onNewOutput(key *InternalKey) []byte {
	l.limit = nil
	// For flushes being split across multiple sstables, call
	// findL0Limit to find the next L0 limit.
	if key != nil {
		l.limit = l.c.findL0Limit(key.UserKey)
	} else {
		// Use the start key of the first pending tombstone to find the
		// next limit. All pending tombstones have the same start key.
		// We use this as opposed to the end key of the
		// last written sstable to effectively handle cases like these:
		//
		// a.SET.3
		// (L0 limit at b)
		// d.RANGEDEL.4:f
		//
		// In this case, the partition after b has only range deletions,
		// so if we were to find the L0 limit after the last written
		// key at the split point (key a), we'd get the limit b again,
		// and finishOutput() would not advance any further because
		// the next range tombstone to write does not start until after
		// the L0 split point.
		startKey := l.c.rangeDelFrag.Start()
		if startKey != nil {
			l.limit = l.c.findL0Limit(startKey)
		}
	}
	return l.limit
}

// splitterGroup is a compactionOutputSplitter that splits whenever one of its
// child splitters advises a compaction split.
type splitterGroup struct {
	cmp       Compare
	splitters []compactionOutputSplitter
}

func (a *splitterGroup) shouldSplitBefore(
	key *InternalKey, tw *sstable.Writer,
) (suggestion compactionSplitSuggestion) {
	for _, splitter := range a.splitters {
		if splitter.shouldSplitBefore(key, tw) == splitNow {
			return splitNow
		}
	}
	return noSplit
}

func (a *splitterGroup) onNewOutput(key *InternalKey) []byte {
	var earliestLimit []byte
	for _, splitter := range a.splitters {
		limit := splitter.onNewOutput(key)
		if limit == nil {
			continue
		}
		if earliestLimit == nil || a.cmp(limit, earliestLimit) < 0 {
			earliestLimit = limit
		}
	}
	return earliestLimit
}

// userKeyChangeSplitter is a compactionOutputSplitter that takes in a child
// splitter, and splits when 1) that child splitter has advised a split, and 2)
// the compaction output is at the boundary between two user keys (also
// the boundary between atomic compaction units). Use this splitter to wrap
// any splitters that don't guarantee user key splits (i.e. splitters that make
// their determination in ways other than comparing the current key against a
// limit key.
type userKeyChangeSplitter struct {
	cmp                Compare
	splitOnNextUserKey bool
	savedKey           []byte
	splitter           compactionOutputSplitter
}

func (u *userKeyChangeSplitter) shouldSplitBefore(
	key *InternalKey, tw *sstable.Writer,
) compactionSplitSuggestion {
	if u.splitOnNextUserKey && u.cmp(u.savedKey, key.UserKey) != 0 {
		u.splitOnNextUserKey = false
		u.savedKey = u.savedKey[:0]
		return splitNow
	}
	if split := u.splitter.shouldSplitBefore(key, tw); split == splitNow {
		u.splitOnNextUserKey = true
		u.savedKey = append(u.savedKey[:0], key.UserKey...)
		return noSplit
	}
	return noSplit
}

func (u *userKeyChangeSplitter) onNewOutput(key *InternalKey) []byte {
	return u.splitter.onNewOutput(key)
}

// compactionFile is a vfs.File wrapper that, on every write, updates a metric
// in `versions` on bytes written by in-progress compactions so far. It also
// increments a per-compaction `written` int.
type compactionFile struct {
	vfs.File

	versions *versionSet
	written  *int64
}

// Write implements the io.Writer interface.
func (c *compactionFile) Write(p []byte) (n int, err error) {
	n, err = c.File.Write(p)
	if err != nil {
		return n, err
	}

	*c.written += int64(n)
	c.versions.incrementCompactionBytes(int64(n))
	return n, err
}

type compactionKind int

const (
	compactionKindDefault compactionKind = iota
	compactionKindFlush
	compactionKindMove
	compactionKindDeleteOnly
	compactionKindElisionOnly
	compactionKindRead
)

func (k compactionKind) String() string {
	switch k {
	case compactionKindDefault:
		return "default"
	case compactionKindFlush:
		return "flush"
	case compactionKindMove:
		return "move"
	case compactionKindDeleteOnly:
		return "delete-only"
	case compactionKindElisionOnly:
		return "elision-only"
	case compactionKindRead:
		return "read"
	}
	return "?"
}

// compaction is a table compaction from one level to the next, starting from a
// given version.
type compaction struct {
	kind      compactionKind
	cmp       Compare
	formatKey base.FormatKey
	logger    Logger
	version   *version

	score float64

	// startLevel is the level that is being compacted. Inputs from startLevel
	// and outputLevel will be merged to produce a set of outputLevel files.
	startLevel *compactionLevel
	// outputLevel is the level that files are being produced in. outputLevel is
	// equal to startLevel+1 except when startLevel is 0 in which case it is
	// equal to compactionPicker.baseLevel().
	outputLevel *compactionLevel

	inputs []compactionLevel

	// maxOutputFileSize is the maximum size of an individual table created
	// during compaction.
	maxOutputFileSize uint64
	// maxOverlapBytes is the maximum number of bytes of overlap allowed for a
	// single output table with the tables in the grandparent level.
	maxOverlapBytes uint64
	// disableRangeTombstoneElision disables elision of range tombstones. Used by
	// tests to allow range tombstones to be added to tables where they would
	// otherwise be elided.
	disableRangeTombstoneElision bool

	// flushing contains the flushables (aka memtables) that are being flushed.
	flushing flushableList
	// bytesIterated contains the number of bytes that have been flushed/compacted.
	bytesIterated uint64
	// bytesWritten contains the number of bytes that have been written to outputs.
	bytesWritten int64
	// atomicBytesIterated points to the variable to increment during iteration.
	// atomicBytesIterated must be read/written atomically. Flushing will increment
	// the shared variable which compaction will read. This allows for the
	// compaction routine to know how many bytes have been flushed before the flush
	// is applied.
	atomicBytesIterated *uint64

	// The boundaries of the input data.
	smallest InternalKey
	largest  InternalKey

	// The range deletion tombstone fragmenter. Adds range tombstones as they are
	// returned from `compactionIter` and fragments them for output to files.
	// Referenced by `compactionIter` which uses it to check whether keys are deleted.
	rangeDelFrag rangedel.Fragmenter

	// A list of objects to close when the compaction finishes. Used by input
	// iteration to keep rangeDelIters open for the lifetime of the compaction,
	// and only close them when the compaction finishes.
	closers []io.Closer

	// grandparents are the tables in level+2 that overlap with the files being
	// compacted. Used to determine output table boundaries. Do not assume that the actual files
	// in the grandparent when this compaction finishes will be the same.
	grandparents manifest.LevelSlice

	// Boundaries at which flushes to L0 should be split. Determined by
	// L0Sublevels. If nil, flushes aren't split.
	l0Limits [][]byte

	// List of disjoint inuse key ranges the compaction overlaps with in
	// grandparent and lower levels. See setupInuseKeyRanges() for the
	// construction. Used by elideTombstone() and elideRangeTombstone() to
	// determine if keys affected by a tombstone possibly exist at a lower level.
	inuseKeyRanges      []manifest.UserKeyRange
	elideTombstoneIndex int

	// allowedZeroSeqNum is true if seqnums can be zeroed if there are no
	// snapshots requiring them to be kept. This determination is made by
	// looking for an sstable which overlaps the bounds of the compaction at a
	// lower level in the LSM during runCompaction.
	allowedZeroSeqNum bool

	metrics map[int]*LevelMetrics
}

func (c *compaction) makeInfo(jobID int) CompactionInfo {
	info := CompactionInfo{
		JobID:  jobID,
		Reason: c.kind.String(),
		Input:  make([]LevelInfo, 0, len(c.inputs)),
	}
	for _, cl := range c.inputs {
		inputInfo := LevelInfo{Level: cl.level, Tables: nil}
		iter := cl.files.Iter()
		for m := iter.First(); m != nil; m = iter.Next() {
			inputInfo.Tables = append(inputInfo.Tables, m.TableInfo())
		}
		info.Input = append(info.Input, inputInfo)
	}
	if c.outputLevel != nil {
		info.Output.Level = c.outputLevel.level
		// If there are no inputs from the output level (eg, a move
		// compaction), add an empty LevelInfo to info.Input.
		if len(c.inputs) > 0 && c.inputs[len(c.inputs)-1].level != c.outputLevel.level {
			info.Input = append(info.Input, LevelInfo{Level: c.outputLevel.level})
		}
	} else {
		// For a delete-only compaction, set the output level to L6. The
		// output level is not meaningful here, but complicating the
		// info.Output interface with a pointer doesn't seem worth the
		// semantic distinction.
		info.Output.Level = numLevels - 1
	}
	return info
}

func newCompaction(pc *pickedCompaction, opts *Options, bytesCompacted *uint64) *compaction {
	c := &compaction{
		kind:                compactionKindDefault,
		cmp:                 pc.cmp,
		formatKey:           opts.Comparer.FormatKey,
		score:               pc.score,
		inputs:              pc.inputs,
		smallest:            pc.smallest,
		largest:             pc.largest,
		logger:              opts.Logger,
		version:             pc.version,
		maxOutputFileSize:   pc.maxOutputFileSize,
		maxOverlapBytes:     pc.maxOverlapBytes,
		atomicBytesIterated: bytesCompacted,
	}
	c.startLevel = &c.inputs[0]
	c.outputLevel = &c.inputs[1]

	// Compute the set of outputLevel+1 files that overlap this compaction (these
	// are the grandparent sstables).
	if c.outputLevel.level+1 < numLevels {
		c.grandparents = c.version.Overlaps(c.outputLevel.level+1, c.cmp,
			c.smallest.UserKey, c.largest.UserKey)
	}
	c.setupInuseKeyRanges()

	switch {
	case pc.readTriggered:
		c.kind = compactionKindRead
	case c.startLevel.level == numLevels-1:
		// This compaction is an L6->L6 elision-only compaction to rewrite
		// a sstable without unnecessary tombstones.
		c.kind = compactionKindElisionOnly
	case c.outputLevel.files.Empty() && c.startLevel.files.Len() == 1 &&
		c.grandparents.SizeSum() <= c.maxOverlapBytes:
		// This compaction can be converted into a trivial move from one level
		// to the next. We avoid such a move if there is lots of overlapping
		// grandparent data. Otherwise, the move could create a parent file
		// that will require a very expensive merge later on.
		c.kind = compactionKindMove
	}
	return c
}

func newDeleteOnlyCompaction(opts *Options, cur *version, inputs []compactionLevel) *compaction {
	c := &compaction{
		kind:      compactionKindDeleteOnly,
		cmp:       opts.Comparer.Compare,
		formatKey: opts.Comparer.FormatKey,
		logger:    opts.Logger,
		version:   cur,
		inputs:    inputs,
	}

	// Set c.smallest, c.largest.
	files := make([]manifest.LevelIterator, 0, len(inputs))
	for _, in := range inputs {
		files = append(files, in.files.Iter())
	}
	c.smallest, c.largest = manifest.KeyRange(opts.Comparer.Compare, files...)
	return c
}

func adjustGrandparentOverlapBytesForFlush(c *compaction, flushingBytes uint64) {
	// Heuristic to place a lower bound on compaction output file size
	// caused by Lbase. Prior to this heuristic we have observed an L0 in
	// production with 310K files of which 290K files were < 10KB in size.
	// Our hypothesis is that it was caused by L1 having 2600 files and
	// ~10GB, such that each flush got split into many tiny files due to
	// overlapping with most of the files in Lbase.
	//
	// The computation below is general in that it accounts
	// for flushing different volumes of data (e.g. we may be flushing
	// many memtables). For illustration, we consider the typical
	// example of flushing a 64MB memtable. So 12.8MB output,
	// based on the compression guess below. If the compressed bytes
	// guess is an over-estimate we will end up with smaller files,
	// and if an under-estimate we will end up with larger files.
	// With a 2MB target file size, 7 files. We are willing to accept
	// 4x the number of files, if it results in better write amplification
	// when later compacting to Lbase, i.e., ~450KB files (target file
	// size / 4).
	//
	// Note that this is a pessimistic heuristic in that
	// fileCountUpperBoundDueToGrandparents could be far from the actual
	// number of files produced due to the grandparent limits. For
	// example, in the extreme, consider a flush that overlaps with 1000
	// files in Lbase f0...f999, and the initially calculated value of
	// maxOverlapBytes will cause splits at f10, f20,..., f990, which
	// means an upper bound file count of 100 files. Say the input bytes
	// in the flush are such that acceptableFileCount=10. We will fatten
	// up maxOverlapBytes by 10x to ensure that the upper bound file count
	// drops to 10. However, it is possible that in practice, even without
	// this change, we would have produced no more than 10 files, and that
	// this change makes the files unnecessarily wide. Say the input bytes
	// are distributed such that 10% are in f0...f9, 10% in f10...f19, ...
	// 10% in f80...f89 and 10% in f990...f999. The original value of
	// maxOverlapBytes would have actually produced only 10 sstables. But
	// by increasing maxOverlapBytes by 10x, we may produce 1 sstable that
	// spans f0...f89, i.e., a much wider sstable than necessary.
	//
	// We could produce a tighter estimate of
	// fileCountUpperBoundDueToGrandparents if we had knowledge of the key
	// distribution of the flush. The 4x multiplier mentioned earlier is
	// a way to try to compensate for this pessimism.
	//
	// TODO(sumeer): we don't have compression info for the data being
	// flushed, but it is likely that existing files that overlap with
	// this flush in Lbase are representative wrt compression ratio. We
	// could store the uncompressed size in FileMetadata and estimate
	// the compression ratio.
	const approxCompressionRatio = 0.2
	approxOutputBytes := approxCompressionRatio * float64(flushingBytes)
	approxNumFilesBasedOnTargetSize :=
		int(math.Ceil(approxOutputBytes / float64(c.maxOutputFileSize)))
	acceptableFileCount := float64(4 * approxNumFilesBasedOnTargetSize)
	// The byte calculation is linear in numGrandparentFiles, but we will
	// incur this linear cost in findGrandparentLimit too, so we are also
	// willing to pay it now. We could approximate this cheaply by using
	// the mean file size of Lbase.
	grandparentFileBytes := c.grandparents.SizeSum()
	fileCountUpperBoundDueToGrandparents :=
		float64(grandparentFileBytes) / float64(c.maxOverlapBytes)
	if fileCountUpperBoundDueToGrandparents > acceptableFileCount {
		c.maxOverlapBytes = uint64(
			float64(c.maxOverlapBytes) *
				(fileCountUpperBoundDueToGrandparents / acceptableFileCount))
	}
}

func newFlush(
	opts *Options, cur *version, baseLevel int, flushing flushableList, bytesFlushed *uint64,
) *compaction {
	c := &compaction{
		kind:                compactionKindFlush,
		cmp:                 opts.Comparer.Compare,
		formatKey:           opts.Comparer.FormatKey,
		logger:              opts.Logger,
		version:             cur,
		inputs:              []compactionLevel{{level: -1}, {level: 0}},
		maxOutputFileSize:   math.MaxUint64,
		maxOverlapBytes:     math.MaxUint64,
		flushing:            flushing,
		atomicBytesIterated: bytesFlushed,
	}
	c.startLevel = &c.inputs[0]
	c.outputLevel = &c.inputs[1]
	if cur.L0Sublevels != nil {
		c.l0Limits = cur.L0Sublevels.FlushSplitKeys()
	}

	smallestSet, largestSet := false, false
	updatePointBounds := func(iter internalIterator) {
		if key, _ := iter.First(); key != nil {
			if !smallestSet ||
				base.InternalCompare(c.cmp, c.smallest, *key) > 0 {
				smallestSet = true
				c.smallest = key.Clone()
			}
		}
		if key, _ := iter.Last(); key != nil {
			if !largestSet ||
				base.InternalCompare(c.cmp, c.largest, *key) < 0 {
				largestSet = true
				c.largest = key.Clone()
			}
		}
	}

	updateRangeBounds := func(iter internalIterator) {
		if key, _ := iter.First(); key != nil {
			if !smallestSet ||
				base.InternalCompare(c.cmp, c.smallest, *key) > 0 {
				smallestSet = true
				c.smallest = key.Clone()
			}
		}
		if key, value := iter.Last(); key != nil {
			tmp := base.InternalKey{
				UserKey: value,
				Trailer: key.Trailer,
			}
			if !largestSet ||
				base.InternalCompare(c.cmp, c.largest, tmp) < 0 {
				largestSet = true
				c.largest = tmp.Clone()
			}
		}
	}

	var flushingBytes uint64
	for i := range flushing {
		f := flushing[i]
		updatePointBounds(f.newIter(nil))
		if rangeDelIter := f.newRangeDelIter(nil); rangeDelIter != nil {
			updateRangeBounds(rangeDelIter)
		}
		flushingBytes += f.inuseBytes()
	}

	if opts.FlushSplitBytes > 0 {
		c.maxOutputFileSize = uint64(opts.Level(0).TargetFileSize)
		c.maxOverlapBytes = maxGrandparentOverlapBytes(opts, 0)
		c.grandparents = c.version.Overlaps(baseLevel, c.cmp,
			c.smallest.UserKey, c.largest.UserKey)
		adjustGrandparentOverlapBytesForFlush(c, flushingBytes)
	}

	c.setupInuseKeyRanges()
	return c
}

func (c *compaction) setupInuseKeyRanges() {
	level := c.outputLevel.level + 1
	if c.outputLevel.level == 0 {
		level = 0
	}
	c.inuseKeyRanges = calculateInuseKeyRanges(c.version, c.cmp, level,
		c.smallest.UserKey, c.largest.UserKey)
}

func calculateInuseKeyRanges(
	v *version, cmp base.Compare, level int, smallest, largest []byte,
) []manifest.UserKeyRange {
	// Use two slices, alternating which one is input and which one is output
	// as we descend the LSM.
	var input, output []manifest.UserKeyRange

	// L0 requires special treatment, since sstables within L0 may overlap.
	// We use the L0 Sublevels structure to efficiently calculate the merged
	// in-use key ranges.
	if level == 0 {
		output = v.L0Sublevels.InUseKeyRanges(smallest, largest)
		level++
	}

	for ; level < numLevels; level++ {
		overlaps := v.Overlaps(level, cmp, smallest, largest)
		iter := overlaps.Iter()

		// We may already have in-use key ranges from higher levels. Iterate
		// through both our accumulated in-use key ranges and this level's
		// files, merging the two.
		//
		// Tables higher within the LSM have broader key spaces. We use this
		// when possible to seek past a level's files that are contained by
		// our current accumulated in-use key ranges. This helps avoid
		// per-sstable work during flushes or compactions in high levels which
		// overlap the majority of the LSM's sstables.
		input, output = output, input
		output = output[:0]

		var currFile *fileMetadata
		var currAccum *manifest.UserKeyRange
		if len(input) > 0 {
			currAccum, input = &input[0], input[1:]
		}

		// If we have an accumulated key range and its start is ≤ smallest,
		// we can seek to the accumulated range's end. Otherwise, we need to
		// start at the first overlapping file within the level.
		if currAccum != nil && cmp(currAccum.Start, smallest) <= 0 {
			currFile = seekGT(&iter, cmp, currAccum.End)
		} else {
			currFile = iter.First()
		}

		for currFile != nil || currAccum != nil {
			// If we've exhausted either the files in the level or the
			// accumulated key ranges, we just need to append the one we have.
			// If we have both a currFile and a currAccum, they either overlap
			// or they're disjoint. If they're disjoint, we append whichever
			// one sorts first and move on to the next file or range. If they
			// overlap, we merge them into currAccum and proceed to the next
			// file.
			switch {
			case currAccum == nil || (currFile != nil && cmp(currFile.Largest.UserKey, currAccum.Start) < 0):
				// This file is strictly before the current accumulated range,
				// or there are no more accumulated ranges.
				output = append(output, manifest.UserKeyRange{
					Start: currFile.Smallest.UserKey,
					End:   currFile.Largest.UserKey,
				})
				currFile = iter.Next()
			case currFile == nil || (currAccum != nil && cmp(currAccum.End, currFile.Smallest.UserKey) < 0):
				// The current accumulated key range is strictly before the
				// current file, or there are no more files.
				output = append(output, *currAccum)
				currAccum = nil
				if len(input) > 0 {
					currAccum, input = &input[0], input[1:]
				}
			default:
				// The current accumulated range and the current file overlap.
				// Adjust the accumulated range to be the union.
				if cmp(currFile.Smallest.UserKey, currAccum.Start) < 0 {
					currAccum.Start = currFile.Smallest.UserKey
				}
				if cmp(currFile.Largest.UserKey, currAccum.End) > 0 {
					currAccum.End = currFile.Largest.UserKey
				}

				// Extending `currAccum`'s end boundary may have caused it to
				// overlap with `input` key ranges that we haven't processed
				// yet. Merge any such key ranges.
				for len(input) > 0 && cmp(input[0].Start, currAccum.End) <= 0 {
					if cmp(input[0].End, currAccum.End) > 0 {
						currAccum.End = input[0].End
					}
					input = input[1:]
				}
				// Seek the level iterator past our current accumulated end.
				currFile = seekGT(&iter, cmp, currAccum.End)
			}
		}
	}
	return output
}

func seekGT(iter *manifest.LevelIterator, cmp base.Compare, key []byte) *manifest.FileMetadata {
	f := iter.SeekGE(cmp, key)
	for f != nil && cmp(f.Largest.UserKey, key) == 0 {
		f = iter.Next()
	}
	return f
}

// findGrandparentLimit takes the start user key for a table and returns the
// user key to which that table can extend without excessively overlapping
// the grandparent level. If no limit is needed considering the grandparent
// files, this function returns nil. This is done in order to prevent a table
// at level N from overlapping too much data at level N+1. We want to avoid
// such large overlaps because they translate into large compactions. The
// current heuristic stops output of a table if the addition of another key
// would cause the table to overlap more than 10x the target file size at
// level N. See maxGrandparentOverlapBytes.
//
// TODO(peter): Stopping compaction output in the middle of a user-key creates
// 2 sstables that need to be compacted together as an "atomic compaction
// unit". This is unfortunate as it removes the benefit of stopping output to
// an sstable in order to prevent a large compaction with the next level. Seems
// better to adjust findGrandparentLimit to not stop output in the middle of a
// user-key. Perhaps this isn't a problem if the compaction picking heuristics
// always pick the right (older) sibling for compaction first.
func (c *compaction) findGrandparentLimit(start []byte) []byte {
	iter := c.grandparents.Iter()
	var overlappedBytes uint64
	for f := iter.SeekGE(c.cmp, start); f != nil; f = iter.Next() {
		overlappedBytes += f.Size
		// To ensure forward progress we always return a larger user
		// key than where we started. See comments above clients of
		// this function for how this is used.
		if overlappedBytes > c.maxOverlapBytes && c.cmp(start, f.Largest.UserKey) < 0 {
			return f.Largest.UserKey
		}
	}
	return nil
}

// findL0Limit takes the start key for a table and returns the user key to which
// that table can be extended without hitting the next l0Limit. Having flushed
// sstables "bridging across" an l0Limit could lead to increased L0 -> LBase
// compaction sizes as well as elevated read amplification.
func (c *compaction) findL0Limit(start []byte) []byte {
	if c.startLevel.level > -1 || c.outputLevel.level != 0 || len(c.l0Limits) == 0 {
		return nil
	}
	index := sort.Search(len(c.l0Limits), func(i int) bool {
		return c.cmp(c.l0Limits[i], start) > 0
	})
	if index < len(c.l0Limits) {
		return c.l0Limits[index]
	}
	return nil
}

// errorOnUserKeyOverlap returns an error if the last two written sstables in
// this compaction have revisions of the same user key present in both sstables,
// when it shouldn't (eg. when splitting flushes).
func (c *compaction) errorOnUserKeyOverlap(ve *versionEdit) error {
	if n := len(ve.NewFiles); n > 1 {
		meta := ve.NewFiles[n-1].Meta
		prevMeta := ve.NewFiles[n-2].Meta
		if prevMeta.Largest.Trailer != InternalKeyRangeDeleteSentinel &&
			c.cmp(prevMeta.Largest.UserKey, meta.Smallest.UserKey) >= 0 {
			return errors.Errorf("pebble: compaction split user key across two sstables: %s in %s and %s",
				prevMeta.Largest.Pretty(c.formatKey),
				prevMeta.FileNum,
				meta.FileNum)
		}
	}
	return nil
}

// allowZeroSeqNum returns true if seqnum's can be zeroed if there are no
// snapshots requiring them to be kept. It performs this determination by
// looking for an sstable which overlaps the bounds of the compaction at a
// lower level in the LSM.
func (c *compaction) allowZeroSeqNum() bool {
	return c.elideRangeTombstone(c.smallest.UserKey, c.largest.UserKey)
}

// elideTombstone returns true if it is ok to elide a tombstone for the
// specified key. A return value of true guarantees that there are no key/value
// pairs at c.level+2 or higher that possibly contain the specified user
// key. The keys in multiple invocations to elideTombstone must be supplied in
// order.
func (c *compaction) elideTombstone(key []byte) bool {
	if len(c.flushing) != 0 {
		return false
	}

	for ; c.elideTombstoneIndex < len(c.inuseKeyRanges); c.elideTombstoneIndex++ {
		r := &c.inuseKeyRanges[c.elideTombstoneIndex]
		if c.cmp(key, r.End) <= 0 {
			if c.cmp(key, r.Start) >= 0 {
				return false
			}
			break
		}
	}
	return true
}

// elideRangeTombstone returns true if it is ok to elide the specified range
// tombstone. A return value of true guarantees that there are no key/value
// pairs at c.outputLevel.level+1 or higher that possibly overlap the specified
// tombstone.
func (c *compaction) elideRangeTombstone(start, end []byte) bool {
	// Disable range tombstone elision if the testing knob for that is enabled,
	// or if we are flushing memtables. The latter requirement is due to
	// inuseKeyRanges not accounting for key ranges in other memtables that are
	// being flushed in the same compaction. It's possible for a range tombstone
	// in one memtable to overlap keys in a preceding memtable in c.flushing.
	//
	// This function is also used in setting allowZeroSeqNum, so disabling
	// elision of range tombstones also disables zeroing of SeqNums.
	//
	// TODO(peter): we disable zeroing of seqnums during flushing to match
	// RocksDB behavior and to avoid generating overlapping sstables during
	// DB.replayWAL. When replaying WAL files at startup, we flush after each
	// WAL is replayed building up a single version edit that is
	// applied. Because we don't apply the version edit after each flush, this
	// code doesn't know that L0 contains files and zeroing of seqnums should
	// be disabled. That is fixable, but it seems safer to just match the
	// RocksDB behavior for now.
	if c.disableRangeTombstoneElision || len(c.flushing) != 0 {
		return false
	}

	lower := sort.Search(len(c.inuseKeyRanges), func(i int) bool {
		return c.cmp(c.inuseKeyRanges[i].End, start) >= 0
	})
	upper := sort.Search(len(c.inuseKeyRanges), func(i int) bool {
		return c.cmp(c.inuseKeyRanges[i].Start, end) > 0
	})
	return lower >= upper
}

// newInputIter returns an iterator over all the input tables in a compaction.
func (c *compaction) newInputIter(newIters tableNewIters) (_ internalIterator, retErr error) {
	if len(c.flushing) != 0 {
		if len(c.flushing) == 1 {
			f := c.flushing[0]
			iter := f.newFlushIter(nil, &c.bytesIterated)
			if rangeDelIter := f.newRangeDelIter(nil); rangeDelIter != nil {
				return newMergingIter(c.logger, c.cmp, nil, iter, rangeDelIter), nil
			}
			return iter, nil
		}
		iters := make([]internalIterator, 0, 2*len(c.flushing))
		for i := range c.flushing {
			f := c.flushing[i]
			iters = append(iters, f.newFlushIter(nil, &c.bytesIterated))
			rangeDelIter := f.newRangeDelIter(nil)
			if rangeDelIter != nil {
				iters = append(iters, rangeDelIter)
			}
		}
		return newMergingIter(c.logger, c.cmp, nil, iters...), nil
	}

	// Check that the LSM ordering invariants are ok in order to prevent
	// generating corrupted sstables due to a violation of those invariants.
	if c.startLevel.level >= 0 {
		err := manifest.CheckOrdering(c.cmp, c.formatKey,
			manifest.Level(c.startLevel.level), c.startLevel.files.Iter())
		if err != nil {
			return nil, err
		}
	}
	err := manifest.CheckOrdering(c.cmp, c.formatKey,
		manifest.Level(c.outputLevel.level), c.outputLevel.files.Iter())
	if err != nil {
		return nil, err
	}

	iters := make([]internalIterator, 0, 2*c.startLevel.files.Len()+1)
	defer func() {
		if retErr != nil {
			for _, iter := range iters {
				if iter != nil {
					iter.Close()
				}
			}
		}
	}()

	// In normal operation, levelIter iterates over the point operations in a
	// level, and initializes a rangeDelIter pointer for the range deletions in
	// each table. During compaction, we want to iterate over the merged view of
	// point operations and range deletions. In order to do this we create two
	// levelIters per level, one which iterates over the point operations, and
	// one which iterates over the range deletions. These two iterators are
	// combined with a mergingIter.
	newRangeDelIter := func(
		f manifest.LevelFile, _ *IterOptions, bytesIterated *uint64,
	) (internalIterator, internalIterator, error) {
		iter, rangeDelIter, err := newIters(f.FileMetadata, nil /* iter options */, &c.bytesIterated)
		if err == nil {
			// TODO(peter): It is mildly wasteful to open the point iterator only to
			// immediately close it. One way to solve this would be to add new
			// methods to tableCache for creating point and range-deletion iterators
			// independently. We'd only want to use those methods here,
			// though. Doesn't seem worth the hassle in the near term.
			if err = iter.Close(); err != nil {
				rangeDelIter.Close()
				rangeDelIter = nil
			}
		}
		if rangeDelIter != nil {
			// Ensure that rangeDelIter is not closed until the compaction is
			// finished. This is necessary because range tombstone processing
			// requires the range tombstones to be held in memory for up to the
			// lifetime of the compaction.
			c.closers = append(c.closers, rangeDelIter)
			rangeDelIter = noCloseIter{rangeDelIter}

			// Truncate the range tombstones returned by the iterator to the upper
			// bound of the atomic compaction unit. Note that we need do this
			// truncation at read time in order to handle RocksDB generated sstables
			// which do not truncate range tombstones to atomic compaction unit
			// boundaries at write time. Because we're doing the truncation at read
			// time, we follow RocksDB's lead and do not truncate tombstones to
			// atomic unit boundaries at compaction time.
			atomicUnit, _ := expandToAtomicUnit(c.cmp, f.Slice(), true /* disableIsCompacting */)
			lowerBound, upperBound := manifest.KeyRange(c.cmp, atomicUnit.Iter())
			// Range deletion tombstones are often written to sstables
			// untruncated on the end key side. However, they are still only
			// valid within a given file's bounds. The logic for writing range
			// tombstones to an output file sometimes has an incomplete view
			// of range tombstones outside the file's internal key bounds. Skip
			// any range tombstones completely outside file bounds.
			rangeDelIter = rangedel.Truncate(
				c.cmp, rangeDelIter, lowerBound.UserKey, upperBound.UserKey, &f.Smallest, &f.Largest)
		}
		if rangeDelIter == nil {
			rangeDelIter = emptyIter
		}
		return rangeDelIter, nil, err
	}

	iterOpts := IterOptions{logger: c.logger}
	addItersForLevel := func(iters []internalIterator, level *compactionLevel) ([]internalIterator, error) {
		iters = append(iters, newLevelIter(iterOpts, c.cmp, nil /* split */, newIters,
			level.files.Iter(), manifest.Level(level.level), &c.bytesIterated))
		// Add the range deletion iterator for each file as an independent level
		// in mergingIter, as opposed to making a levelIter out of those. This
		// is safer as levelIter expects all keys coming from underlying
		// iterators to be in order. Due to compaction / tombstone writing
		// logic in finishOutput(), it is possible for range tombstones to not
		// be strictly ordered across all files in one level.
		//
		// Consider this example from the metamorphic tests (also repeated in
		// finishOutput()), consisting of three L3 files with their bounds
		// specified in square brackets next to the file name:
		//
		// ./000240.sst   [tmgc#391,MERGE-tmgc#391,MERGE]
		// tmgc#391,MERGE [786e627a]
		// tmgc-udkatvs#331,RANGEDEL
		//
		// ./000241.sst   [tmgc#384,MERGE-tmgc#384,MERGE]
		// tmgc#384,MERGE [666c7070]
		// tmgc-tvsalezade#383,RANGEDEL
		// tmgc-tvsalezade#331,RANGEDEL
		//
		// ./000242.sst   [tmgc#383,RANGEDEL-tvsalezade#72057594037927935,RANGEDEL]
		// tmgc-tvsalezade#383,RANGEDEL
		// tmgc#375,SET [72646c78766965616c72776865676e79]
		// tmgc-tvsalezade#356,RANGEDEL
		//
		// Here, the range tombstone in 000240.sst falls "after" one in
		// 000241.sst, despite 000240.sst being ordered "before" 000241.sst for
		// levelIter's purposes. While each file is still consistent before its
		// bounds, it's safer to have all rangedel iterators be visible to
		// mergingIter.
		iter := level.files.Iter()
		for f := iter.First(); f != nil; f = iter.Next() {
			rangeDelIter, _, err := newRangeDelIter(iter.Take(), nil, &c.bytesIterated)
			if err != nil {
				return nil, errors.Wrapf(err, "pebble: could not open table %s", errors.Safe(f.FileNum))
			}
			if rangeDelIter != emptyIter {
				iters = append(iters, rangeDelIter)
			}
		}
		return iters, nil
	}

	if c.startLevel.level != 0 {
		iters, err = addItersForLevel(iters, c.startLevel)
		if err != nil {
			return nil, err
		}
	} else {
		iter := c.startLevel.files.Iter()
		for f := iter.First(); f != nil; f = iter.Next() {
			iter, rangeDelIter, err := newIters(iter.Current(), nil /* iter options */, &c.bytesIterated)
			if err != nil {
				return nil, errors.Wrapf(err, "pebble: could not open table %s", errors.Safe(f.FileNum))
			}
			iters = append(iters, iter)
			if rangeDelIter != nil {
				iters = append(iters, rangeDelIter)
			}
		}
	}

	iters, err = addItersForLevel(iters, c.outputLevel)
	if err != nil {
		return nil, err
	}
	return newMergingIter(c.logger, c.cmp, nil, iters...), nil
}

func (c *compaction) String() string {
	if len(c.flushing) != 0 {
		return "flush\n"
	}

	var buf bytes.Buffer
	for i := range c.inputs {
		level := c.startLevel.level
		if i == 1 {
			level = c.outputLevel.level
		}
		fmt.Fprintf(&buf, "%d:", level)
		iter := c.inputs[i].files.Iter()
		for f := iter.First(); f != nil; f = iter.Next() {
			fmt.Fprintf(&buf, " %s:%s-%s", f.FileNum, f.Smallest, f.Largest)
		}
		fmt.Fprintf(&buf, "\n")
	}
	return buf.String()
}

type manualCompaction struct {
	// Count of the retries either due to too many concurrent compactions, or a
	// concurrent compaction to overlapping levels.
	retries     int
	level       int
	outputLevel int
	done        chan error
	start       InternalKey
	end         InternalKey
}

type readCompaction struct {
	level int
	// Key ranges are used instead of file handles as versions could change
	// between the read sampling and scheduling a compaction.
	start []byte
	end   []byte
}

func (d *DB) addInProgressCompaction(c *compaction) {
	d.mu.compact.inProgress[c] = struct{}{}
	var isBase, isIntraL0 bool
	for _, cl := range c.inputs {
		iter := cl.files.Iter()
		for f := iter.First(); f != nil; f = iter.Next() {
			if f.Compacting {
				d.opts.Logger.Fatalf("L%d->L%d: %s already being compacted", c.startLevel.level, c.outputLevel.level, f.FileNum)
			}
			f.Compacting = true
			if c.startLevel != nil && c.outputLevel != nil && c.startLevel.level == 0 {
				if c.outputLevel.level == 0 {
					f.IsIntraL0Compacting = true
					isIntraL0 = true
				} else {
					isBase = true
				}
			}
		}
	}

	if (isIntraL0 || isBase) && c.version.L0Sublevels != nil {
		l0Inputs := []manifest.LevelSlice{c.startLevel.files}
		if isIntraL0 {
			l0Inputs = append(l0Inputs, c.outputLevel.files)
		}
		if err := c.version.L0Sublevels.UpdateStateForStartedCompaction(l0Inputs, isBase); err != nil {
			d.opts.Logger.Fatalf("could not update state for compaction: %s", err)
		}
	}

	if false {
		// TODO(peter): Do we want to keep this? It is useful for seeing the
		// concurrent compactions/flushes that are taking place. Right now, this
		// spams the logs and output to tests. Figure out a way to useful expose
		// it.
		strs := make([]string, 0, len(d.mu.compact.inProgress))
		for c := range d.mu.compact.inProgress {
			var s string
			if c.startLevel.level == -1 {
				s = fmt.Sprintf("mem->L%d", c.outputLevel.level)
			} else {
				s = fmt.Sprintf("L%d->L%d:%.1f", c.startLevel.level, c.outputLevel.level, c.score)
			}
			strs = append(strs, s)
		}
		// This odd sorting function is intended to sort "mem" before "L*".
		sort.Slice(strs, func(i, j int) bool {
			if strs[i][0] == strs[j][0] {
				return strs[i] < strs[j]
			}
			return strs[i] > strs[j]
		})
		d.opts.Logger.Infof("compactions: %s", strings.Join(strs, " "))
	}
}

// Removes compaction markers from files in a compaction.
//
// DB.mu must be held when calling this method. All writes to the manifest
// for this compaction should have completed by this point.
func (d *DB) removeInProgressCompaction(c *compaction) {
	for _, cl := range c.inputs {
		iter := cl.files.Iter()
		for f := iter.First(); f != nil; f = iter.Next() {
			if !f.Compacting {
				d.opts.Logger.Fatalf("L%d->L%d: %s not being compacted", c.startLevel.level, c.outputLevel.level, f.FileNum)
			}
			f.Compacting = false
			f.IsIntraL0Compacting = false
		}
	}
	delete(d.mu.compact.inProgress, c)

	l0InProgress := inProgressL0Compactions(d.getInProgressCompactionInfoLocked(c))
	d.mu.versions.currentVersion().L0Sublevels.InitCompactingFileInfo(l0InProgress)
}

func (d *DB) getCompactionPacerInfo() compactionPacerInfo {
	bytesFlushed := atomic.LoadUint64(&d.atomic.bytesFlushed)

	d.mu.Lock()
	estimatedMaxWAmp := d.mu.versions.picker.getEstimatedMaxWAmp()
	pacerInfo := compactionPacerInfo{
		slowdownThreshold:   uint64(estimatedMaxWAmp * float64(d.opts.MemTableSize)),
		totalCompactionDebt: d.mu.versions.picker.estimatedCompactionDebt(bytesFlushed),
	}
	for _, m := range d.mu.mem.queue {
		pacerInfo.totalDirtyBytes += m.inuseBytes()
	}
	d.mu.Unlock()

	return pacerInfo
}

func (d *DB) getFlushPacerInfo() flushPacerInfo {
	var pacerInfo flushPacerInfo
	d.mu.Lock()
	for _, m := range d.mu.mem.queue {
		pacerInfo.inuseBytes += m.inuseBytes()
	}
	d.mu.Unlock()
	return pacerInfo
}

func (d *DB) getDeletionPacerInfo() deletionPacerInfo {
	var pacerInfo deletionPacerInfo
	// Call GetDiskUsage after every file deletion. This may seem inefficient,
	// but in practice this was observed to take constant time, regardless of
	// volume size used, at least on linux with ext4 and zfs. All invocations
	// take 10 microseconds or less.
	if space, err := d.opts.FS.GetDiskUsage(d.dirname); err == nil {
		pacerInfo.freeBytes = space.AvailBytes
	}
	d.mu.Lock()
	pacerInfo.obsoleteBytes = d.mu.versions.metrics.Table.ObsoleteSize
	pacerInfo.liveBytes = uint64(d.mu.versions.metrics.Total().Size)
	d.mu.Unlock()
	return pacerInfo
}

// maybeScheduleFlush schedules a flush if necessary.
//
// d.mu must be held when calling this.
func (d *DB) maybeScheduleFlush() {
	if d.mu.compact.flushing || d.closed.Load() != nil || d.opts.ReadOnly {
		return
	}
	if len(d.mu.mem.queue) <= 1 {
		return
	}

	if !d.passedFlushThreshold() {
		return
	}

	d.mu.compact.flushing = true
	go d.flush()
}

func (d *DB) passedFlushThreshold() bool {
	var n int
	var size uint64
	for ; n < len(d.mu.mem.queue)-1; n++ {
		if !d.mu.mem.queue[n].readyForFlush() {
			break
		}
		if d.mu.mem.queue[n].flushForced {
			// A flush was forced. Pretend the memtable size is the configured
			// size. See minFlushSize below.
			size += uint64(d.opts.MemTableSize)
		} else {
			size += d.mu.mem.queue[n].totalBytes()
		}
	}
	if n == 0 {
		// None of the immutable memtables are ready for flushing.
		return false
	}

	// Only flush once the sum of the queued memtable sizes exceeds half the
	// configured memtable size. This prevents flushing of memtables at startup
	// while we're undergoing the ramp period on the memtable size. See
	// DB.newMemTable().
	minFlushSize := uint64(d.opts.MemTableSize) / 2
	if size < minFlushSize {
		return false
	}

	return true
}

func (d *DB) maybeScheduleDelayedFlush(tbl *memTable) {
	var mem *flushableEntry
	for _, m := range d.mu.mem.queue {
		if m.flushable == tbl {
			mem = m
			break
		}
	}
	if mem == nil || mem.flushForced || mem.delayedFlushForced {
		return
	}
	mem.delayedFlushForced = true
	go func() {
		timer := time.NewTimer(d.opts.Experimental.DeleteRangeFlushDelay)
		defer timer.Stop()

		select {
		case <-d.closedCh:
			return
		case <-mem.flushed:
			return
		case <-timer.C:
			d.commit.mu.Lock()
			defer d.commit.mu.Unlock()
			d.mu.Lock()
			defer d.mu.Unlock()

			// NB: The timer may fire concurrently with a call to Close.  If a
			// Close call beat us to acquiring d.mu, d.closed is 1, and it's
			// too late to flush anything. Otherwise, the Close call will
			// block on locking d.mu until we've finished scheduling the flush
			// and set `d.mu.compact.flushing` to true. Close will wait for
			// the current flush to complete.
			if d.closed.Load() != nil {
				return
			}

			if d.mu.mem.mutable == tbl {
				d.makeRoomForWrite(nil)
			} else {
				mem.flushForced = true
				d.maybeScheduleFlush()
			}
		}
	}()
}

func (d *DB) flush() {
	pprof.Do(context.Background(), flushLabels, func(context.Context) {
		d.mu.Lock()
		defer d.mu.Unlock()
		if err := d.flush1(); err != nil {
			// TODO(peter): count consecutive flush errors and backoff.
			d.opts.EventListener.BackgroundError(err)
		}
		d.mu.compact.flushing = false
		// More flush work may have arrived while we were flushing, so schedule
		// another flush if needed.
		d.maybeScheduleFlush()
		// The flush may have produced too many files in a level, so schedule a
		// compaction if needed.
		d.maybeScheduleCompaction()
		d.mu.compact.cond.Broadcast()
	})
}

// flush runs a compaction that copies the immutable memtables from memory to
// disk.
//
// d.mu must be held when calling this, but the mutex may be dropped and
// re-acquired during the course of this method.
func (d *DB) flush1() error {
	var n int
	for ; n < len(d.mu.mem.queue)-1; n++ {
		if !d.mu.mem.queue[n].readyForFlush() {
			break
		}
	}
	if n == 0 {
		// None of the immutable memtables are ready for flushing.
		return nil
	}

	// Require that every memtable being flushed has a log number less than the
	// new minimum unflushed log number.
	minUnflushedLogNum := d.mu.mem.queue[n].logNum
	if !d.opts.DisableWAL {
		for i := 0; i < n; i++ {
			logNum := d.mu.mem.queue[i].logNum
			if logNum >= minUnflushedLogNum {
				return errFlushInvariant
			}
		}
	}

	c := newFlush(d.opts, d.mu.versions.currentVersion(),
		d.mu.versions.picker.getBaseLevel(), d.mu.mem.queue[:n], &d.atomic.bytesFlushed)
	d.addInProgressCompaction(c)

	jobID := d.mu.nextJobID
	d.mu.nextJobID++
	d.opts.EventListener.FlushBegin(FlushInfo{
		JobID: jobID,
		Input: n,
	})
	startTime := d.timeNow()

	flushPacer := (pacer)(nilPacer)
	if d.opts.private.enablePacing {
		// TODO(peter): Flush pacing is disabled until we figure out why it impacts
		// throughput.
		flushPacer = newFlushPacer(flushPacerEnv{
			limiter:      d.flushLimiter,
			memTableSize: uint64(d.opts.MemTableSize),
			getInfo:      d.getFlushPacerInfo,
		})
	}
	ve, pendingOutputs, err := d.runCompaction(jobID, c, flushPacer)

	info := FlushInfo{
		JobID:    jobID,
		Input:    n,
		Duration: d.timeNow().Sub(startTime),
		Done:     true,
		Err:      err,
	}
	if err == nil {
		for i := range ve.NewFiles {
			e := &ve.NewFiles[i]
			info.Output = append(info.Output, e.Meta.TableInfo())
		}
		if len(ve.NewFiles) == 0 {
			info.Err = errEmptyTable
		}

		// The flush succeeded or it produced an empty sstable. In either case we
		// want to bump the minimum unflushed log number to the log number of the
		// oldest unflushed memtable.
		ve.MinUnflushedLogNum = minUnflushedLogNum
		metrics := c.metrics[0]
		for i := 0; i < n; i++ {
			metrics.BytesIn += d.mu.mem.queue[i].logSize
		}

		d.mu.versions.logLock()
		err = d.mu.versions.logAndApply(jobID, ve, c.metrics, d.dataDir,
			func() []compactionInfo { return d.getInProgressCompactionInfoLocked(c) })
		if err != nil {
			// TODO(peter): untested.
			d.mu.versions.obsoleteTables = append(d.mu.versions.obsoleteTables, pendingOutputs...)
			d.mu.versions.incrementObsoleteTablesLocked(pendingOutputs)
		}
	}

	d.maybeUpdateDeleteCompactionHints(c)
	d.removeInProgressCompaction(c)
	d.mu.versions.incrementCompactions(c.kind)
	d.mu.versions.incrementCompactionBytes(-c.bytesWritten)
	d.opts.EventListener.FlushEnd(info)

	// Refresh bytes flushed count.
	atomic.StoreUint64(&d.atomic.bytesFlushed, 0)

	var flushed flushableList
	if err == nil {
		flushed = d.mu.mem.queue[:n]
		d.mu.mem.queue = d.mu.mem.queue[n:]
		d.updateReadStateLocked(d.opts.DebugCheck)
		d.updateTableStatsLocked(ve.NewFiles)
	}
	d.deleteObsoleteFiles(jobID, false /* waitForOngoing */)

	// Mark all the memtables we flushed as flushed. Note that we do this last so
	// that a synchronous call to DB.Flush() will not return until the deletion
	// of obsolete files from this job have completed. This makes testing easier
	// and provides similar behavior to manual compactions where the compaction
	// is not marked as completed until the deletion of obsolete files job has
	// completed.
	for i := range flushed {
		// The order of these operations matters here for ease of testing. Removing
		// the reader reference first allows tests to be guaranteed that the
		// memtable reservation has been released by the time a synchronous flush
		// returns.
		flushed[i].readerUnref()
		close(flushed[i].flushed)
	}
	return err
}

// maybeScheduleCompaction schedules a compaction if necessary.
//
// d.mu must be held when calling this.
func (d *DB) maybeScheduleCompaction() {
	d.maybeScheduleCompactionPicker(pickAuto)
}

func pickAuto(picker compactionPicker, env compactionEnv) *pickedCompaction {
	return picker.pickAuto(env)
}

func pickElisionOnly(picker compactionPicker, env compactionEnv) *pickedCompaction {
	return picker.pickElisionOnlyCompaction(env)
}

// maybeScheduleCompactionPicker schedules a compaction if necessary,
// calling `pickFunc` to pick automatic compactions.
//
// d.mu must be held when calling this.
func (d *DB) maybeScheduleCompactionPicker(
	pickFunc func(compactionPicker, compactionEnv) *pickedCompaction,
) {
	if d.closed.Load() != nil || d.opts.ReadOnly {
		return
	}
	if d.mu.compact.compactingCount >= d.opts.MaxConcurrentCompactions {
		if len(d.mu.compact.manual) > 0 {
			// Inability to run head blocks later manual compactions.
			d.mu.compact.manual[0].retries++
		}
		return
	}

	// Compaction picking needs a coherent view of a Version. In particular, we
	// need to exlude concurrent ingestions from making a decision on which level
	// to ingest into that conflicts with our compaction
	// decision. versionSet.logLock provides the necessary mutual exclusion.
	d.mu.versions.logLock()
	defer d.mu.versions.logUnlock()

	// Check for the closed flag again, in case the DB was closed while we were
	// waiting for logLock().
	if d.closed.Load() != nil {
		return
	}

	env := compactionEnv{
		bytesCompacted:          &d.atomic.bytesCompacted,
		earliestSnapshotSeqNum:  d.mu.snapshots.earliest(),
		earliestUnflushedSeqNum: d.getEarliestUnflushedSeqNumLocked(),
	}

	// Check for delete-only compactions first, because they're expected to be
	// cheap and reduce future compaction work.
	if len(d.mu.compact.deletionHints) > 0 &&
		d.mu.compact.compactingCount < d.opts.MaxConcurrentCompactions &&
		!d.opts.private.disableAutomaticCompactions {
		v := d.mu.versions.currentVersion()
		snapshots := d.mu.snapshots.toSlice()
		inputs, unresolvedHints := checkDeleteCompactionHints(d.cmp, v, d.mu.compact.deletionHints, snapshots)
		d.mu.compact.deletionHints = unresolvedHints

		if len(inputs) > 0 {
			c := newDeleteOnlyCompaction(d.opts, v, inputs)
			d.mu.compact.compactingCount++
			d.addInProgressCompaction(c)
			go d.compact(c, nil)
		}
	}

	for len(d.mu.compact.manual) > 0 && d.mu.compact.compactingCount < d.opts.MaxConcurrentCompactions {
		manual := d.mu.compact.manual[0]
		env.inProgressCompactions = d.getInProgressCompactionInfoLocked(nil)
		pc, retryLater := d.mu.versions.picker.pickManual(env, manual)
		if pc != nil {
			c := newCompaction(pc, d.opts, env.bytesCompacted)
			d.mu.compact.manual = d.mu.compact.manual[1:]
			d.mu.compact.compactingCount++
			d.addInProgressCompaction(c)
			go d.compact(c, manual.done)
		} else if !retryLater {
			// Noop
			d.mu.compact.manual = d.mu.compact.manual[1:]
			manual.done <- nil
		} else {
			// Inability to run head blocks later manual compactions.
			manual.retries++
			break
		}
	}

	for !d.opts.private.disableAutomaticCompactions && d.mu.compact.compactingCount < d.opts.MaxConcurrentCompactions {
		env.inProgressCompactions = d.getInProgressCompactionInfoLocked(nil)
		env.readCompactionEnv = readCompactionEnv{
			readCompactions: &d.mu.compact.readCompactions,
			flushing:        d.mu.compact.flushing || d.passedFlushThreshold(),
		}
		pc := pickFunc(d.mu.versions.picker, env)
		if pc == nil {
			break
		}
		c := newCompaction(pc, d.opts, env.bytesCompacted)
		d.mu.compact.compactingCount++
		d.addInProgressCompaction(c)
		go d.compact(c, nil)
	}
}

// A deleteCompactionHint records a user key and sequence number span that has been
// deleted by a range tombstone. A hint is recorded if at least one sstable
// falls completely within both the user key and sequence number spans.
// Once the tombstones and the observed completely-contained sstables fall
// into the same snapshot stripe, a delete-only compaction may delete any
// sstables within the range.
type deleteCompactionHint struct {
	start []byte
	end   []byte
	// The level of the file containing the range tombstone(s) when the hint
	// was created. Only lower levels need to be searched for files that may
	// be deleted.
	tombstoneLevel int
	// The file containing the range tombstone(s) that created the hint.
	tombstoneFile *fileMetadata
	// The smallest and largest sequence numbers of the abutting tombstones
	// merged to form this hint. All of a tables' keys must be less than the
	// tombstone smallest sequence number to be deleted. All of a tables'
	// sequence numbers must fall into the same snapshot stripe as the
	// tombstone largest sequence number to be deleted.
	tombstoneLargestSeqNum  uint64
	tombstoneSmallestSeqNum uint64
	// The smallest sequence number of a sstable that was found to be covered
	// by this hint. The hint cannot be resolved until this sequence number is
	// in the same snapshot stripe as the largest tombstone sequence number.
	// This is set when a hint is created, so the LSM may look different and
	// notably no longer contian the sstable that contained the key at this
	// sequence number.
	fileSmallestSeqNum uint64
}

func (h deleteCompactionHint) String() string {
	return fmt.Sprintf("L%d.%s %s-%s seqnums(tombstone=%d-%d, file-smallest=%d)",
		h.tombstoneLevel, h.tombstoneFile.FileNum, h.start, h.end,
		h.tombstoneSmallestSeqNum, h.tombstoneLargestSeqNum, h.fileSmallestSeqNum)
}

func (h *deleteCompactionHint) canDelete(cmp Compare, m *fileMetadata, snapshots []uint64) bool {
	// The file can only be deleted if all of its keys are older than the
	// earliest tombstone aggregated into the hint.
	if m.LargestSeqNum >= h.tombstoneSmallestSeqNum || m.SmallestSeqNum < h.fileSmallestSeqNum {
		return false
	}

	// The file's oldest key must  be in the same snapshot stripe as the
	// newest tombstone. NB: We already checked the hint's sequence numbers,
	// but this file's oldest sequence number might be lower than the hint's
	// smallest sequence number despite the file falling within the key range
	// if this file was constructed after the hint by a compaction.
	ti, _ := snapshotIndex(h.tombstoneLargestSeqNum, snapshots)
	fi, _ := snapshotIndex(m.SmallestSeqNum, snapshots)
	if ti != fi {
		return false
	}

	// The file's keys must be completely contianed within the hint range.
	return cmp(h.start, m.Smallest.UserKey) <= 0 && cmp(m.Largest.UserKey, h.end) < 0
}

func (d *DB) maybeUpdateDeleteCompactionHints(c *compaction) {
	// Compactions that zero sequence numbers can interfere with compaction
	// deletion hints. Deletion hints apply to tables containing keys older
	// than a threshold. If a key more recent than the threshold is zeroed in
	// a compaction, a delete-only compaction may mistake it as meeting the
	// threshold and drop a table containing live data.
	//
	// To avoid this scenario, compactions that zero sequence numbers remove
	// any conflicting deletion hints. A deletion hint is conflicting if both
	// of the following conditions apply:
	// * its key space overlaps with the compaction
	// * at least one of its inputs contains a key as recent as one of the
	//   hint's tombstones.
	//
	if !c.allowedZeroSeqNum {
		return
	}

	updatedHints := d.mu.compact.deletionHints[:0]
	for _, h := range d.mu.compact.deletionHints {
		// If the compaction's key space is disjoint from the hint's key
		// space, the zeroing of sequence numbers won't affect the hint. Keep
		// the hint.
		keysDisjoint := d.cmp(h.end, c.smallest.UserKey) < 0 || d.cmp(h.start, c.largest.UserKey) > 0
		if keysDisjoint {
			updatedHints = append(updatedHints, h)
			continue
		}

		// All of the compaction's inputs must be older than the hint's
		// tombstones.
		inputsOlder := true
		for _, in := range c.inputs {
			iter := in.files.Iter()
			for f := iter.First(); f != nil; f = iter.Next() {
				inputsOlder = inputsOlder && f.LargestSeqNum < h.tombstoneSmallestSeqNum
			}
		}
		if inputsOlder {
			updatedHints = append(updatedHints, h)
			continue
		}

		// Drop h, because the compaction c may have zeroed sequence numbers
		// of keys more recent than some of h's tombstones.
	}
	d.mu.compact.deletionHints = updatedHints
}

func checkDeleteCompactionHints(
	cmp Compare, v *version, hints []deleteCompactionHint, snapshots []uint64,
) ([]compactionLevel, []deleteCompactionHint) {
	var files map[*fileMetadata]bool
	var byLevel [numLevels][]*fileMetadata

	unresolvedHints := hints[:0]
	for _, h := range hints {
		// Check each compaction hint to see if it's resolvable. Resolvable
		// hints are removed and trigger a delete-only compaction if any files
		// in the current LSM still meet their criteria. Unresolvable hints
		// are saved and don't trigger a delete-only compaction.
		//
		// When a compaction hint is created, the sequence numbers of the
		// range tombstones and the covered file with the oldest key are
		// recorded. The largest tombstone sequence number and the smallest
		// file sequence number must be in the same snapshot stripe for the
		// hint to be resolved. The below graphic models a compaction hint
		// covering the keyspace [b, r). The hint completely contains two
		// files, 000002 and 000003. The file 000003 contains the lowest
		// covered sequence number at #90. The tombstone b.RANGEDEL.230:h has
		// the highest tombstone sequence number incorporated into the hint.
		// The hint may be resolved only once the snapshots at #100, #180 and
		// #210 are all closed. File 000001 is not included within the hint
		// because it extends beyond the range tombstones in user key space.
		//
		// 250
		//
		//       |-b...230:h-|
		// _____________________________________________________ snapshot #210
		// 200               |--h.RANGEDEL.200:r--|
		//
		// _____________________________________________________ snapshot #180
		//
		// 150                     +--------+
		//           +---------+   | 000003 |
		//           | 000002  |   |        |
		//           +_________+   |        |
		// 100_____________________|________|___________________ snapshot #100
		//                         +--------+
		// _____________________________________________________ snapshot #70
		//                             +---------------+
		//  50                         | 000001        |
		//                             |               |
		//                             +---------------+
		// ______________________________________________________________
		//     a b c d e f g h i j k l m n o p q r s t u v w x y z

		ti, _ := snapshotIndex(h.tombstoneLargestSeqNum, snapshots)
		fi, _ := snapshotIndex(h.fileSmallestSeqNum, snapshots)
		if ti != fi {
			// Cannot resolve yet.
			unresolvedHints = append(unresolvedHints, h)
			continue
		}

		// The hint h will be resolved and dropped, regardless of whether
		// there are any tables that can be deleted.
		for l := h.tombstoneLevel + 1; l < numLevels; l++ {
			overlaps := v.Overlaps(l, cmp, h.start, h.end)
			iter := overlaps.Iter()
			for m := iter.First(); m != nil; m = iter.Next() {
				if m.Compacting || !h.canDelete(cmp, m, snapshots) || files[m] {
					continue
				}

				if files == nil {
					// Construct files lazily, assuming most calls will not
					// produce delete-only compactions.
					files = make(map[*fileMetadata]bool)
				}
				files[m] = true
				byLevel[l] = append(byLevel[l], m)
			}
		}
	}

	var compactLevels []compactionLevel
	for l, files := range byLevel {
		if len(files) == 0 {
			continue
		}
		compactLevels = append(compactLevels, compactionLevel{
			level: l,
			files: manifest.NewLevelSliceKeySorted(cmp, files),
		})
	}
	return compactLevels, unresolvedHints
}

// compact runs one compaction and maybe schedules another call to compact.
func (d *DB) compact(c *compaction, errChannel chan error) {
	pprof.Do(context.Background(), compactLabels, func(context.Context) {
		d.mu.Lock()
		defer d.mu.Unlock()
		if err := d.compact1(c, errChannel); err != nil {
			// TODO(peter): count consecutive compaction errors and backoff.
			d.opts.EventListener.BackgroundError(err)
		}
		d.mu.compact.compactingCount--
		// The previous compaction may have produced too many files in a
		// level, so reschedule another compaction if needed.
		d.maybeScheduleCompaction()
		d.mu.compact.cond.Broadcast()
	})
}

// compact1 runs one compaction.
//
// d.mu must be held when calling this, but the mutex may be dropped and
// re-acquired during the course of this method.
func (d *DB) compact1(c *compaction, errChannel chan error) (err error) {
	if errChannel != nil {
		defer func() {
			errChannel <- err
		}()
	}

	jobID := d.mu.nextJobID
	d.mu.nextJobID++
	info := c.makeInfo(jobID)
	d.opts.EventListener.CompactionBegin(info)
	startTime := d.timeNow()

	compactionPacer := (pacer)(nilPacer)
	if d.opts.private.enablePacing {
		// TODO(peter): Compaction pacing is disabled until we figure out why it
		// impacts throughput.
		compactionPacer = newCompactionPacer(compactionPacerEnv{
			limiter:      d.compactionLimiter,
			memTableSize: uint64(d.opts.MemTableSize),
			getInfo:      d.getCompactionPacerInfo,
		})
	}
	ve, pendingOutputs, err := d.runCompaction(jobID, c, compactionPacer)

	info.Duration = d.timeNow().Sub(startTime)
	if err == nil {
		d.mu.versions.logLock()
		err = d.mu.versions.logAndApply(jobID, ve, c.metrics, d.dataDir, func() []compactionInfo {
			return d.getInProgressCompactionInfoLocked(c)
		})
		if err != nil {
			// TODO(peter): untested.
			d.mu.versions.obsoleteTables = append(d.mu.versions.obsoleteTables, pendingOutputs...)
			d.mu.versions.incrementObsoleteTablesLocked(pendingOutputs)
		}
	}

	info.Done = true
	info.Err = err
	if err == nil {
		for i := range ve.NewFiles {
			e := &ve.NewFiles[i]
			info.Output.Tables = append(info.Output.Tables, e.Meta.TableInfo())
		}
	}

	d.maybeUpdateDeleteCompactionHints(c)
	d.removeInProgressCompaction(c)
	d.mu.versions.incrementCompactions(c.kind)
	d.mu.versions.incrementCompactionBytes(-c.bytesWritten)
	d.opts.EventListener.CompactionEnd(info)

	// Update the read state before deleting obsolete files because the
	// read-state update will cause the previous version to be unref'd and if
	// there are no references obsolete tables will be added to the obsolete
	// table list.
	if err == nil {
		d.updateReadStateLocked(d.opts.DebugCheck)
		d.updateTableStatsLocked(ve.NewFiles)
	}
	d.deleteObsoleteFiles(jobID, true /* waitForOngoing */)

	return err
}

// runCompactions runs a compaction that produces new on-disk tables from
// memtables or old on-disk tables.
//
// d.mu must be held when calling this, but the mutex may be dropped and
// re-acquired during the course of this method.
func (d *DB) runCompaction(
	jobID int, c *compaction, pacer pacer,
) (ve *versionEdit, pendingOutputs []*fileMetadata, retErr error) {
	// Check for a delete-only compaction. This can occur when wide range
	// tombstones completely contain sstables.
	if c.kind == compactionKindDeleteOnly {
		c.metrics = make(map[int]*LevelMetrics, len(c.inputs))
		ve := &versionEdit{
			DeletedFiles: map[deletedFileEntry]*fileMetadata{},
		}
		for _, cl := range c.inputs {
			levelMetrics := &LevelMetrics{}
			iter := cl.files.Iter()
			for f := iter.First(); f != nil; f = iter.Next() {
				levelMetrics.NumFiles--
				levelMetrics.Size -= int64(f.Size)
				ve.DeletedFiles[deletedFileEntry{
					Level:   cl.level,
					FileNum: f.FileNum,
				}] = f
			}
			c.metrics[cl.level] = levelMetrics
		}
		return ve, nil, nil
	}

	// Check for a trivial move of one table from one level to the next. We avoid
	// such a move if there is lots of overlapping grandparent data. Otherwise,
	// the move could create a parent file that will require a very expensive
	// merge later on.
	if c.kind == compactionKindMove {
		iter := c.startLevel.files.Iter()
		meta := iter.First()
		c.metrics = map[int]*LevelMetrics{
			c.startLevel.level: {
				NumFiles: -1,
				Size:     -int64(meta.Size),
			},
			c.outputLevel.level: {
				NumFiles:    1,
				Size:        int64(meta.Size),
				BytesMoved:  meta.Size,
				TablesMoved: 1,
			},
		}
		ve := &versionEdit{
			DeletedFiles: map[deletedFileEntry]*fileMetadata{
				{Level: c.startLevel.level, FileNum: meta.FileNum}: meta,
			},
			NewFiles: []newFileEntry{
				{Level: c.outputLevel.level, Meta: meta},
			},
		}
		return ve, nil, nil
	}

	defer func() {
		if retErr != nil {
			pendingOutputs = nil
		}
	}()

	snapshots := d.mu.snapshots.toSlice()

	// Release the d.mu lock while doing I/O.
	// Note the unusual order: Unlock and then Lock.
	d.mu.Unlock()
	defer d.mu.Lock()

	iiter, err := c.newInputIter(d.newIters)
	if err != nil {
		return nil, pendingOutputs, err
	}
	c.allowedZeroSeqNum = c.allowZeroSeqNum()
	iter := newCompactionIter(c.cmp, c.formatKey, d.merge, iiter, snapshots,
		&c.rangeDelFrag, c.allowedZeroSeqNum, c.elideTombstone, c.elideRangeTombstone)

	var (
		filenames []string
		tw        *sstable.Writer
	)
	defer func() {
		if iter != nil {
			retErr = firstError(retErr, iter.Close())
		}
		if tw != nil {
			retErr = firstError(retErr, tw.Close())
		}
		if retErr != nil {
			for _, filename := range filenames {
				d.opts.FS.Remove(filename)
			}
		}
		for _, closer := range c.closers {
			retErr = firstError(retErr, closer.Close())
		}
	}()

	ve = &versionEdit{
		DeletedFiles: map[deletedFileEntry]*fileMetadata{},
	}

	outputMetrics := &LevelMetrics{
		BytesIn:   c.startLevel.files.SizeSum(),
		BytesRead: c.outputLevel.files.SizeSum(),
	}
	outputMetrics.BytesRead += outputMetrics.BytesIn
	c.metrics = map[int]*LevelMetrics{
		c.outputLevel.level: outputMetrics,
	}
	if len(c.flushing) == 0 && c.metrics[c.startLevel.level] == nil {
		c.metrics[c.startLevel.level] = &LevelMetrics{}
	}

	writerOpts := d.opts.MakeWriterOptions(c.outputLevel.level)

	newOutput := func() error {
		fileMeta := &fileMetadata{}
		d.mu.Lock()
		fileNum := d.mu.versions.getNextFileNum()
		fileMeta.FileNum = fileNum
		pendingOutputs = append(pendingOutputs, fileMeta)
		d.mu.Unlock()

		filename := base.MakeFilename(d.opts.FS, d.dirname, fileTypeTable, fileNum)
		file, err := d.opts.FS.Create(filename)
		if err != nil {
			return err
		}
		reason := "flushing"
		if c.flushing == nil {
			reason = "compacting"
		}
		d.opts.EventListener.TableCreated(TableCreateInfo{
			JobID:   jobID,
			Reason:  reason,
			Path:    filename,
			FileNum: fileNum,
		})
		file = vfs.NewSyncingFile(file, vfs.SyncingFileOptions{
			BytesPerSync: d.opts.BytesPerSync,
		})
		file = &compactionFile{
			File:     file,
			versions: d.mu.versions,
			written:  &c.bytesWritten,
		}
		filenames = append(filenames, filename)
		cacheOpts := private.SSTableCacheOpts(d.cacheID, fileNum).(sstable.WriterOption)
		internalTableOpt := private.SSTableInternalTableOpt.(sstable.WriterOption)
		tw = sstable.NewWriter(file, writerOpts, cacheOpts, internalTableOpt)

		fileMeta.CreationTime = time.Now().Unix()
		ve.NewFiles = append(ve.NewFiles, newFileEntry{
			Level: c.outputLevel.level,
			Meta:  fileMeta,
		})
		return nil
	}

	splitL0Outputs := c.outputLevel.level == 0 && d.opts.FlushSplitBytes > 0

	// finishOutput is called with the a user key up to which all tombstones
	// should be flushed. Typically, this is the first key of the next
	// sstable or an empty key if this output is the final sstable.
	finishOutput := func(splitKey []byte) error {
		// If we haven't output any point records to the sstable (tw == nil)
		// then the sstable will only contain range tombstones. The smallest
		// key in the sstable will be the start key of the first range
		// tombstone added. We need to ensure that this start key is distinct
		// from the splitKey passed to finishOutput (if set), otherwise we
		// would generate an sstable where the largest key is smaller than the
		// smallest key due to how the largest key boundary is set below.
		// NB: It is permissible for the range tombstone start key to be the
		// empty string.
		// TODO: It is unfortunate that we have to do this check here rather
		// than when we decide to finish the sstable in the runCompaction
		// loop. A better structure currently eludes us.
		if tw == nil {
			startKey := c.rangeDelFrag.Start()
			if len(iter.tombstones) > 0 {
				startKey = iter.tombstones[0].Start.UserKey
			}
			if splitKey != nil && d.cmp(startKey, splitKey) == 0 {
				return nil
			}
		}

		// NB: clone the key because the data can be held on to by the call to
		// compactionIter.Tombstones via rangedel.Fragmenter.FlushTo.
		splitKey = append([]byte(nil), splitKey...)
		for _, v := range iter.Tombstones(splitKey, splitL0Outputs) {
			if tw == nil {
				if err := newOutput(); err != nil {
					return err
				}
			}
			// The tombstone being added could be completely outside the
			// eventual bounds of the sstable. Consider this example (bounds
			// in square brackets next to table filename):
			//
			// ./000240.sst   [tmgc#391,MERGE-tmgc#391,MERGE]
			// tmgc#391,MERGE [786e627a]
			// tmgc-udkatvs#331,RANGEDEL
			//
			// ./000241.sst   [tmgc#384,MERGE-tmgc#384,MERGE]
			// tmgc#384,MERGE [666c7070]
			// tmgc-tvsalezade#383,RANGEDEL
			// tmgc-tvsalezade#331,RANGEDEL
			//
			// ./000242.sst   [tmgc#383,RANGEDEL-tvsalezade#72057594037927935,RANGEDEL]
			// tmgc-tvsalezade#383,RANGEDEL
			// tmgc#375,SET [72646c78766965616c72776865676e79]
			// tmgc-tvsalezade#356,RANGEDEL
			//
			// Note that both of the top two SSTables have range tombstones
			// that start after the file's end keys. Since the file bound
			// computation happens well after all range tombstones have been
			// added to the writer, eliding out-of-file range tombstones based
			// on sequence number at this stage is difficult, and necessitates
			// read-time logic to ignore range tombstones outside file bounds.
			if err := tw.Add(v.Start, v.End); err != nil {
				return err
			}
		}

		if tw == nil {
			return nil
		}

		if err := tw.Close(); err != nil {
			tw = nil
			return err
		}
		writerMeta, err := tw.Metadata()
		if err != nil {
			tw = nil
			return err
		}
		tw = nil
		meta := ve.NewFiles[len(ve.NewFiles)-1].Meta
		meta.Size = writerMeta.Size
		meta.SmallestSeqNum = writerMeta.SmallestSeqNum
		meta.LargestSeqNum = writerMeta.LargestSeqNum
		// If the file didn't contain any range deletions, we can fill its
		// table stats now, avoiding unnecessarily loading the table later.
		maybeSetStatsFromProperties(meta, &writerMeta.Properties)

		if c.flushing == nil {
			outputMetrics.TablesCompacted++
			outputMetrics.BytesCompacted += meta.Size
		} else {
			outputMetrics.TablesFlushed++
			outputMetrics.BytesFlushed += meta.Size
		}
		outputMetrics.Size += int64(meta.Size)
		outputMetrics.NumFiles++

		// The handling of range boundaries is a bit complicated.
		if n := len(ve.NewFiles); n > 1 {
			// This is not the first output file. Bound the smallest range key by the
			// previous tables largest key.
			prevMeta := ve.NewFiles[n-2].Meta
			if writerMeta.SmallestRange.UserKey != nil {
				c := d.cmp(writerMeta.SmallestRange.UserKey, prevMeta.Largest.UserKey)
				if c < 0 {
					return errors.Errorf(
						"pebble: smallest range tombstone start key is less than previous sstable largest key: %s < %s",
						writerMeta.SmallestRange.Pretty(d.opts.Comparer.FormatKey),
						prevMeta.Largest.Pretty(d.opts.Comparer.FormatKey))
				}
				if c == 0 && prevMeta.Largest.SeqNum() <= writerMeta.SmallestRange.SeqNum() {
					// The user key portion of the range boundary start key is equal to
					// the previous table's largest key. We need the tables to be
					// key-space partitioned, so force the boundary to a key that we know
					// is larger than the previous table's largest key.
					if prevMeta.Largest.SeqNum() == 0 {
						// If the seqnum of the previous table's largest key is 0, we can't
						// decrement it. This should never happen as we take care in the
						// main compaction loop to avoid generating an sstable with a
						// largest key containing a zero seqnum.
						return errors.Errorf(
							"pebble: previous sstable largest key unexpectedly has 0 seqnum: %s",
							prevMeta.Largest.Pretty(d.opts.Comparer.FormatKey))
					}
					// TODO(peter): Technically, this produces a small gap with the
					// previous sstable. The largest key of the previous table may be
					// b#5.SET. The smallest key of the new sstable may then become
					// b#4.RANGEDEL even though the tombstone is [b,z)#6. If iteration
					// ever precisely truncates sstable boundaries, the key b#5.DEL at
					// a lower level could slip through. Note that this can't ever
					// actually happen, though, because the only way for two records to
					// have the same seqnum is via ingestion. And even if it did happen
					// revealing a deletion tombstone is not problematic. Slightly more
					// worrisome is the combination of b#5.MERGE, b#5.SET and
					// b#4.RANGEDEL, but we can't ever see b#5.MERGE and b#5.SET at
					// different levels in the tree due to the ingestion argument and
					// atomic compaction units.
					//
					// TODO(sumeer): Incorporate the the comment in
					// https://github.com/cockroachdb/pebble/pull/479#pullrequestreview-340600654
					// into docs/range_deletions.md and reference the correctness
					// argument here. Note that that comment might be slightly incorrect.
					writerMeta.SmallestRange.SetSeqNum(prevMeta.Largest.SeqNum() - 1)
				}
			}
		}

		if splitKey != nil && writerMeta.LargestRange.UserKey != nil {
			// The current file is not the last output file and there is a range tombstone in it.
			// If the tombstone extends into the next file, then truncate it for the purposes of
			// computing meta.Largest. For example, say the next file's first key is c#7,1 and the
			// current file's last key is c#10,1 and the current file has a range tombstone
			// [b, d)#12,15. For purposes of the bounds we pretend that the range tombstone ends at
			// c#inf where inf is the InternalKeyRangeDeleteSentinel. Note that this is just for
			// purposes of bounds computation -- the current sstable will end up with a Largest key
			// of c#7,1 so the range tombstone in the current file will be able to delete c#7.
			if d.cmp(writerMeta.LargestRange.UserKey, splitKey) >= 0 {
				writerMeta.LargestRange.UserKey = splitKey
				writerMeta.LargestRange.Trailer = InternalKeyRangeDeleteSentinel
			}
		}

		meta.Smallest = writerMeta.Smallest(d.cmp)
		meta.Largest = writerMeta.Largest(d.cmp)

		// Verify that the sstable bounds fall within the compaction input
		// bounds. This is a sanity check that we don't have a logic error
		// elsewhere that causes the sstable bounds to accidentally expand past the
		// compaction input bounds as doing so could lead to various badness such
		// as keys being deleted by a range tombstone incorrectly.
		if c.smallest.UserKey != nil {
			switch v := d.cmp(meta.Smallest.UserKey, c.smallest.UserKey); {
			case v >= 0:
				// Nothing to do.
			case v < 0:
				return errors.Errorf("pebble: compaction output grew beyond bounds of input: %s < %s",
					meta.Smallest.Pretty(d.opts.Comparer.FormatKey),
					c.smallest.Pretty(d.opts.Comparer.FormatKey))
			}
		}
		if c.largest.UserKey != nil {
			switch v := d.cmp(meta.Largest.UserKey, c.largest.UserKey); {
			case v <= 0:
				// Nothing to do.
			case v > 0:
				return errors.Errorf("pebble: compaction output grew beyond bounds of input: %s > %s",
					meta.Largest.Pretty(d.opts.Comparer.FormatKey),
					c.largest.Pretty(d.opts.Comparer.FormatKey))
			}
		}
		// Verify that when splitting an output to L0, we never split different
		// revisions of the same user key across two different sstables.
		if splitL0Outputs {
			if err := c.errorOnUserKeyOverlap(ve); err != nil {
				return err
			}
		}
		if err := meta.Validate(d.cmp, d.opts.Comparer.FormatKey); err != nil {
			return err
		}
		return nil
	}

	// compactionOutputSplitters contain all logic to determine whether the
	// compaction loop should stop writing to one output sstable and switch to
	// a new one. Some splitters can wrap other splitters, and
	// the splitterGroup can be composed of multiple splitters. In this case,
	// we start off with splitters for file sizes, grandparent limits, and (for
	// L0 splits) L0 limits, before wrapping them in an splitterGroup.
	//
	// There is a complication here: We may not be able to switch SSTables
	// right away when we are splitting an L0 output. We do not split the
	// same user key across different sstables within one flush, so the
	// userKeyChangeSplitter ensures we are at a user key change boundary when
	// doing a split.
	outputSplitters := []compactionOutputSplitter{
		&fileSizeSplitter{maxFileSize: c.maxOutputFileSize},
		&grandparentLimitSplitter{c: c, ve: ve},
	}
	var splitter compactionOutputSplitter
	if splitL0Outputs {
		// outputSplitters[0] is the file size splitter, which doesn't guarantee
		// that all advised splits will be at user key change boundaries. Wrap
		// it in a userKeyChangeSplitter.
		outputSplitters[0] = &userKeyChangeSplitter{
			cmp:      c.cmp,
			splitter: outputSplitters[0],
		}
		outputSplitters = append(outputSplitters, &l0LimitSplitter{c: c, ve: ve})
	}
	splitter = &splitterGroup{
		cmp:       c.cmp,
		splitters: outputSplitters,
	}

	// NB: we avoid calling maybeThrottle on a nilPacer because the cost of
	// dynamic dispatch in the hot loop below is pronounced in CPU profiles (see
	// #1030). Additionally, even the cost of this interface comparison is
	// pronounced in CPU profiles, so we hoist the entire thing out of the hot
	// loop. This allows the branch predictor to do its job and make the pacer
	// interactions ~free when a nilPacer is used.
	isNilPacer := pacer == nilPacer

	// Each outer loop iteration produces one output file. An iteration that
	// produces a file containing point keys (and optionally range tombstones)
	// guarantees that the input iterator advanced. An iteration that produces
	// a file containing only range tombstones guarantees the limit passed to
	// `finishOutput()` advanced to a strictly greater user key corresponding
	// to a grandparent file largest key, or nil. Taken together, these
	// progress guarantees ensure that eventually the input iterator will be
	// exhausted and the range tombstone fragments will all be flushed.
	for key, val := iter.First(); key != nil || !c.rangeDelFrag.Empty(); {
		splitterSuggestion := splitter.onNewOutput(key)

		// Each inner loop iteration processes one key from the input iterator.
		prevPointSeqNum := InternalKeySeqNumMax
		for ; key != nil; key, val = iter.Next() {
			if split := splitter.shouldSplitBefore(key, tw); split == splitNow {
				if splitL0Outputs {
					// Flush all tombstones up until key.UserKey, and
					// truncate them at that key.
					//
					// The fragmenter could save the passed-in key. As this
					// key could live beyond the write into the current
					// sstable output file, make a copy.
					c.rangeDelFrag.TruncateAndFlushTo(key.Clone().UserKey)
				}
				break
			}

			atomic.StoreUint64(c.atomicBytesIterated, c.bytesIterated)
			if !isNilPacer {
				if err := pacer.maybeThrottle(c.bytesIterated); err != nil {
					return nil, pendingOutputs, err
				}
			}
			if key.Kind() == InternalKeyKindRangeDelete {
				// Range tombstones are handled specially. They are fragmented and
				// written later during `finishOutput()`. We add them to the
				// `Fragmenter` now to make them visible to `compactionIter` so covered
				// keys in the same snapshot stripe can be elided.
				c.rangeDelFrag.Add(iter.cloneKey(*key), val)
				continue
			}
			if tw == nil {
				if err := newOutput(); err != nil {
					return nil, pendingOutputs, err
				}
			}
			if err := tw.Add(*key, val); err != nil {
				return nil, pendingOutputs, err
			}
			prevPointSeqNum = key.SeqNum()
		}

		// A splitter requested a split, and we're ready to finish the output.
		// We need to choose the key at which to split any pending range
		// tombstones.
		//
		// There's a complication here. We need to ensure that for a user key
		// k we never end up with one output's largest key as k#0 and the
		// next output's smallest key as k#RANGEDEL,#x where x > 0. This is a
		// problem because k#RANGEDEL,#x sorts before k#0.  Normally, we just
		// adjust the seqnum of the next output's smallest boundary to be
		// less, but that's not possible with the zero seqnum. We can avoid
		// this case with careful picking of where to split pending range
		// tombstones.
		var splitKey []byte
		switch {
		case key != nil:
			// We hit the size, grandparent, or L0 limit for the sstable.
			// The next key either has a greater user key than the previous
			// key, or if not, the previous key must not have had a zero
			// sequence number.

			// TODO(jackson): If we hit the grandparent limit, the next
			// grandparent's smallest key may be less than the current key.
			// Splitting at the current key will cause this output to overlap
			// a potentially unbounded number of grandparents.
			splitKey = key.UserKey
		case key == nil && splitL0Outputs:
			// We ran out of keys with flush splits enabled. Set splitKey to
			// nil so all range tombstones get flushed in the current sstable.
			// Consider this example:
			//
			// a.SET.4
			// d.MERGE.5
			// d.RANGEDEL.3:f
			// (no more keys remaining)
			//
			// Where d is a flush split key (i.e. splitterSuggestion = 'd').
			// Since d.MERGE.5 has already been written to this output by this
			// point (as it's <= splitterSuggestion), and flushes cannot have
			// user keys split across multiple sstables, we have to set
			// splitKey to a key greater than 'd' to ensure the range deletion
			// also gets flushed. Setting the splitKey to nil is the simplest
			// way to ensure that.
			//
			// TODO(jackson): This case is only problematic if splitKey equals
			// the user key of the last point key added. We don't need to
			// flush *all* range tombstones to the current sstable. We could
			// flush up to the next grandparent limit greater than
			// `splitterSuggestion` instead.
			splitKey = nil
		case key == nil && prevPointSeqNum != 0:
			// The last key added did not have a zero sequence number, so
			// we'll always be able to adjust the next table's smallest key.
			// NB: Because of the splitter's `onNewOutput` contract,
			// `splitterSuggestion` must be >= any key previously added to the
			// current output sstable.
			splitKey = splitterSuggestion
		case key == nil && prevPointSeqNum == 0:
			// The last key added did have a zero sequence number. The
			// splitters' suggested split point might have the same user key,
			// which would cause the next output to have an unadjustable
			// smallest key. To prevent that, we ignore the splitter's
			// suggestion, leaving splitKey nil to flush all pending range
			// tombstones.
			// TODO(jackson): This case is only problematic if splitKey equals
			// the user key of the last point key added. We don't need to
			// flush *all* range tombstones to the current sstable. We could
			// flush up to the next grandparent limit greater than
			// `splitterSuggestion` instead.
			splitKey = nil
		default:
			return nil, nil, errors.New("pebble: not reached")
		}

		if err := finishOutput(splitKey); err != nil {
			return nil, pendingOutputs, err
		}
	}

	for _, cl := range c.inputs {
		iter := cl.files.Iter()
		for f := iter.First(); f != nil; f = iter.Next() {
			c.metrics[cl.level].NumFiles--
			c.metrics[cl.level].Size -= int64(f.Size)
			ve.DeletedFiles[deletedFileEntry{
				Level:   cl.level,
				FileNum: f.FileNum,
			}] = f
		}
	}

	if err := d.dataDir.Sync(); err != nil {
		return nil, pendingOutputs, err
	}
	return ve, pendingOutputs, nil
}

// scanObsoleteFiles scans the filesystem for files that are no longer needed
// and adds those to the internal lists of obsolete files. Note that the files
// are not actually deleted by this method. A subsequent call to
// deleteObsoleteFiles must be performed. Must be not be called concurrently
// with compactions and flushes. db.mu must be held when calling this function,
// however as this function is expected to only be called during Open(), no
// other operations should be contending on it just yet.
func (d *DB) scanObsoleteFiles(list []string) {
	if d.mu.compact.compactingCount > 0 || d.mu.compact.flushing {
		panic("pebble: cannot scan obsolete files concurrently with compaction/flushing")
	}

	liveFileNums := make(map[FileNum]struct{})
	d.mu.versions.addLiveFileNums(liveFileNums)
	minUnflushedLogNum := d.mu.versions.minUnflushedLogNum
	manifestFileNum := d.mu.versions.manifestFileNum

	var obsoleteLogs []fileInfo
	var obsoleteTables []*fileMetadata
	var obsoleteManifests []fileInfo
	var obsoleteOptions []fileInfo

	for _, filename := range list {
		fileType, fileNum, ok := base.ParseFilename(d.opts.FS, filename)
		if !ok {
			continue
		}
		switch fileType {
		case fileTypeLog:
			if fileNum >= minUnflushedLogNum {
				continue
			}
			fi := fileInfo{fileNum: fileNum}
			if stat, err := d.opts.FS.Stat(filename); err == nil {
				fi.fileSize = uint64(stat.Size())
			}
			obsoleteLogs = append(obsoleteLogs, fi)
		case fileTypeManifest:
			if fileNum >= manifestFileNum {
				continue
			}
			fi := fileInfo{fileNum: fileNum}
			if stat, err := d.opts.FS.Stat(filename); err == nil {
				fi.fileSize = uint64(stat.Size())
			}
			obsoleteManifests = append(obsoleteManifests, fi)
		case fileTypeOptions:
			if fileNum >= d.optionsFileNum {
				continue
			}
			fi := fileInfo{fileNum: fileNum}
			if stat, err := d.opts.FS.Stat(filename); err == nil {
				fi.fileSize = uint64(stat.Size())
			}
			obsoleteOptions = append(obsoleteOptions, fi)
		case fileTypeTable:
			if _, ok := liveFileNums[fileNum]; ok {
				continue
			}
			fileMeta := &fileMetadata{
				FileNum: fileNum,
			}
			if stat, err := d.opts.FS.Stat(filename); err == nil {
				fileMeta.Size = uint64(stat.Size())
			}
			obsoleteTables = append(obsoleteTables, fileMeta)
		default:
			// Don't delete files we don't know about.
			continue
		}
	}

	d.mu.log.queue = merge(d.mu.log.queue, obsoleteLogs)
	d.mu.versions.metrics.WAL.Files += int64(len(obsoleteLogs))
	d.mu.versions.obsoleteTables = mergeFileMetas(d.mu.versions.obsoleteTables, obsoleteTables)
	d.mu.versions.incrementObsoleteTablesLocked(obsoleteTables)
	d.mu.versions.obsoleteManifests = merge(d.mu.versions.obsoleteManifests, obsoleteManifests)
	d.mu.versions.obsoleteOptions = merge(d.mu.versions.obsoleteOptions, obsoleteOptions)
}

// disableFileDeletions disables file deletions and then waits for any
// in-progress deletion to finish. The caller is required to call
// enableFileDeletions in order to enable file deletions again. It is ok for
// multiple callers to disable file deletions simultaneously, though they must
// all invoke enableFileDeletions in order for file deletions to be re-enabled
// (there is an internal reference count on file deletion disablement).
//
// d.mu must be held when calling this method.
func (d *DB) disableFileDeletions() {
	d.mu.cleaner.disabled++
	for d.mu.cleaner.cleaning {
		d.mu.cleaner.cond.Wait()
	}
	d.mu.cleaner.cond.Broadcast()
}

// enableFileDeletions enables previously disabled file deletions. Note that if
// file deletions have been re-enabled, the current goroutine will be used to
// perform the queued up deletions.
//
// d.mu must be held when calling this method.
func (d *DB) enableFileDeletions() {
	if d.mu.cleaner.disabled <= 0 || d.mu.cleaner.cleaning {
		panic("pebble: file deletion disablement invariant violated")
	}
	d.mu.cleaner.disabled--
	if d.mu.cleaner.disabled > 0 {
		return
	}
	jobID := d.mu.nextJobID
	d.mu.nextJobID++
	d.deleteObsoleteFiles(jobID, true /* waitForOngoing */)
}

// d.mu must be held when calling this.
func (d *DB) acquireCleaningTurn(waitForOngoing bool) bool {
	// Only allow a single delete obsolete files job to run at a time.
	for d.mu.cleaner.cleaning && d.mu.cleaner.disabled == 0 && waitForOngoing {
		d.mu.cleaner.cond.Wait()
	}
	if d.mu.cleaner.cleaning {
		return false
	}
	if d.mu.cleaner.disabled > 0 {
		// File deletions are currently disabled. When they are re-enabled a new
		// job will be created to catch up on file deletions.
		return false
	}
	d.mu.cleaner.cleaning = true
	return true
}

// d.mu must be held when calling this.
func (d *DB) releaseCleaningTurn() {
	d.mu.cleaner.cleaning = false
	d.mu.cleaner.cond.Broadcast()
}

// deleteObsoleteFiles deletes those files that are no longer needed. If
// waitForOngoing is true, it waits for any ongoing cleaning turns to complete,
// and if false, it returns rightaway if a cleaning turn is ongoing.
//
// d.mu must be held when calling this, but the mutex may be dropped and
// re-acquired during the course of this method.
func (d *DB) deleteObsoleteFiles(jobID int, waitForOngoing bool) {
	if !d.acquireCleaningTurn(waitForOngoing) {
		return
	}
	d.doDeleteObsoleteFiles(jobID)
	d.releaseCleaningTurn()
}

// obsoleteFile holds information about a file that needs to be deleted soon.
type obsoleteFile struct {
	dir      string
	fileNum  base.FileNum
	fileType fileType
	fileSize uint64
}

type fileInfo struct {
	fileNum  FileNum
	fileSize uint64
}

// d.mu must be held when calling this, but the mutex may be dropped and
// re-acquired during the course of this method.
func (d *DB) doDeleteObsoleteFiles(jobID int) {
	var obsoleteTables []fileInfo

	defer func() {
		for _, tbl := range obsoleteTables {
			delete(d.mu.versions.zombieTables, tbl.fileNum)
		}
	}()

	var obsoleteLogs []fileInfo
	for i := range d.mu.log.queue {
		// NB: d.mu.versions.minUnflushedLogNum is the log number of the earliest
		// log that has not had its contents flushed to an sstable. We can recycle
		// the prefix of d.mu.log.queue with log numbers less than
		// minUnflushedLogNum.
		if d.mu.log.queue[i].fileNum >= d.mu.versions.minUnflushedLogNum {
			obsoleteLogs = d.mu.log.queue[:i]
			d.mu.log.queue = d.mu.log.queue[i:]
			d.mu.versions.metrics.WAL.Files -= int64(len(obsoleteLogs))
			break
		}
	}

	for _, table := range d.mu.versions.obsoleteTables {
		obsoleteTables = append(obsoleteTables, fileInfo{
			fileNum:  table.FileNum,
			fileSize: table.Size,
		})
	}
	d.mu.versions.obsoleteTables = nil

	obsoleteManifests := d.mu.versions.obsoleteManifests
	d.mu.versions.obsoleteManifests = nil

	obsoleteOptions := d.mu.versions.obsoleteOptions
	d.mu.versions.obsoleteOptions = nil

	// Release d.mu while doing I/O
	// Note the unusual order: Unlock and then Lock.
	d.mu.Unlock()
	defer d.mu.Lock()

	files := [4]struct {
		fileType fileType
		obsolete []fileInfo
	}{
		{fileTypeLog, obsoleteLogs},
		{fileTypeTable, obsoleteTables},
		{fileTypeManifest, obsoleteManifests},
		{fileTypeOptions, obsoleteOptions},
	}
	_, noRecycle := d.opts.Cleaner.(base.NeedsFileContents)
	filesToDelete := make([]obsoleteFile, 0, len(files))
	for _, f := range files {
		// We sort to make the order of deletions deterministic, which is nice for
		// tests.
		sort.Slice(f.obsolete, func(i, j int) bool {
			return f.obsolete[i].fileNum < f.obsolete[j].fileNum
		})
		for _, fi := range f.obsolete {
			dir := d.dirname
			switch f.fileType {
			case fileTypeLog:
				if !noRecycle && d.logRecycler.add(fi) {
					continue
				}
				dir = d.walDirname
			case fileTypeTable:
				d.tableCache.evict(fi.fileNum)
			}

			filesToDelete = append(filesToDelete, obsoleteFile{
				dir:      dir,
				fileNum:  fi.fileNum,
				fileType: f.fileType,
				fileSize: fi.fileSize,
			})
		}
	}
	if len(filesToDelete) > 0 {
		d.deleters.Add(1)
		// Delete asynchronously if that could get held up in the pacer.
		if d.opts.Experimental.MinDeletionRate > 0 {
			go d.paceAndDeleteObsoleteFiles(jobID, filesToDelete)
		} else {
			d.paceAndDeleteObsoleteFiles(jobID, filesToDelete)
		}
	}
}

// Paces and eventually deletes the list of obsolete files passed in. db.mu
// must NOT be held when calling this method.
func (d *DB) paceAndDeleteObsoleteFiles(jobID int, files []obsoleteFile) {
	defer d.deleters.Done()
	pacer := (pacer)(nilPacer)
	if d.opts.Experimental.MinDeletionRate > 0 {
		pacer = newDeletionPacer(d.deletionLimiter, d.getDeletionPacerInfo)
	}

	for _, of := range files {
		path := base.MakeFilename(d.opts.FS, of.dir, of.fileType, of.fileNum)
		if of.fileType == fileTypeTable {
			_ = pacer.maybeThrottle(of.fileSize)
			d.mu.Lock()
			d.mu.versions.metrics.Table.ObsoleteCount--
			d.mu.versions.metrics.Table.ObsoleteSize -= of.fileSize
			d.mu.Unlock()
		}
		d.deleteObsoleteFile(of.fileType, jobID, path, of.fileNum)
	}
}

func (d *DB) maybeScheduleObsoleteTableDeletion() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.mu.versions.obsoleteTables) == 0 {
		return
	}
	if !d.acquireCleaningTurn(false) {
		return
	}

	go func() {
		pprof.Do(context.Background(), gcLabels, func(context.Context) {
			d.mu.Lock()
			defer d.mu.Unlock()

			jobID := d.mu.nextJobID
			d.mu.nextJobID++
			d.doDeleteObsoleteFiles(jobID)
			d.releaseCleaningTurn()
		})
	}()
}

// deleteObsoleteFile deletes file that is no longer needed.
func (d *DB) deleteObsoleteFile(fileType fileType, jobID int, path string, fileNum FileNum) {
	// TODO(peter): need to handle this error, probably by re-adding the
	// file that couldn't be deleted to one of the obsolete slices map.
	err := d.opts.Cleaner.Clean(d.opts.FS, fileType, path)
	if oserror.IsNotExist(err) {
		return
	}

	switch fileType {
	case fileTypeLog:
		d.opts.EventListener.WALDeleted(WALDeleteInfo{
			JobID:   jobID,
			Path:    path,
			FileNum: fileNum,
			Err:     err,
		})
	case fileTypeManifest:
		d.opts.EventListener.ManifestDeleted(ManifestDeleteInfo{
			JobID:   jobID,
			Path:    path,
			FileNum: fileNum,
			Err:     err,
		})
	case fileTypeTable:
		d.opts.EventListener.TableDeleted(TableDeleteInfo{
			JobID:   jobID,
			Path:    path,
			FileNum: fileNum,
			Err:     err,
		})
	}
}

func merge(a, b []fileInfo) []fileInfo {
	if len(b) == 0 {
		return a
	}

	a = append(a, b...)
	sort.Slice(a, func(i, j int) bool {
		return a[i].fileNum < a[j].fileNum
	})

	n := 0
	for i := 0; i < len(a); i++ {
		if n == 0 || a[i].fileNum != a[n-1].fileNum {
			a[n] = a[i]
			n++
		}
	}
	return a[:n]
}

func mergeFileMetas(a, b []*fileMetadata) []*fileMetadata {
	if len(b) == 0 {
		return a
	}

	a = append(a, b...)
	sort.Slice(a, func(i, j int) bool {
		return a[i].FileNum < a[j].FileNum
	})

	n := 0
	for i := 0; i < len(a); i++ {
		if n == 0 || a[i].FileNum != a[n-1].FileNum {
			a[n] = a[i]
			n++
		}
	}
	return a[:n]
}
