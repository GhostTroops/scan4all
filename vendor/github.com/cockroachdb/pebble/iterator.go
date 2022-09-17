// Copyright 2011 The LevelDB-Go and Pebble Authors. All rights reserved. Use
// of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package pebble

import (
	"bytes"
	"io"
	"sync/atomic"
	"unsafe"

	"github.com/cockroachdb/errors"
	"github.com/cockroachdb/pebble/internal/base"
	"github.com/cockroachdb/pebble/internal/fastrand"
	"github.com/cockroachdb/pebble/internal/invariants"
	"github.com/cockroachdb/pebble/internal/manifest"
	"github.com/cockroachdb/redact"
)

// iterPos describes the state of the internal iterator, in terms of whether it is
// at the position returned to the user (cur), one ahead of the position returned
// (next for forward iteration and prev for reverse iteration). The cur position
// is split into two states, for forward and reverse iteration, since we need to
// differentiate for switching directions.
type iterPos int8

const (
	iterPosCurForward iterPos = 0
	iterPosNext       iterPos = 1
	iterPosPrev       iterPos = -1
	iterPosCurReverse iterPos = -2

	// For limited iteration. When the iterator is at iterPosCurForwardPaused
	// - Next*() call should behave as if the internal iterator is already
	//   at next (akin to iterPosNext).
	// - Prev*() call should behave as if the internal iterator is at the
	//   current key (akin to iterPosCurForward).
	//
	// Similar semantics apply to CurReversePaused.
	iterPosCurForwardPaused iterPos = 2
	iterPosCurReversePaused iterPos = -3
)

// Approximate gap in bytes between samples of data read during iteration.
// This is multiplied with a default ReadSamplingMultiplier of 1 << 4 to yield
// 1 << 20 (1MB). The 1MB factor comes from:
// https://github.com/cockroachdb/pebble/issues/29#issuecomment-494477985
const readBytesPeriod uint64 = 1 << 16

var errReversePrefixIteration = errors.New("pebble: unsupported reverse prefix iteration")

// IteratorMetrics holds per-iterator metrics. These do not change over the
// lifetime of the iterator.
type IteratorMetrics struct {
	// The read amplification experienced by this iterator. This is the sum of
	// the memtables, the L0 sublevels and the non-empty Ln levels. Higher read
	// amplification generally results in slower reads, though allowing higher
	// read amplification can also result in faster writes.
	ReadAmp int
}

// IteratorStatsKind describes the two kind of iterator stats.
type IteratorStatsKind int8

const (
	// InterfaceCall represents calls to Iterator.
	InterfaceCall IteratorStatsKind = iota
	// InternalIterCall represents calls by Iterator to its internalIterator.
	InternalIterCall
	// NumStatsKind is the number of kinds, and is used for array sizing.
	NumStatsKind
)

// IteratorStats contains iteration stats.
type IteratorStats struct {
	// ForwardSeekCount includes SeekGE, SeekPrefixGE, First.
	ForwardSeekCount [NumStatsKind]int
	// ReverseSeek includes SeekLT, Last.
	ReverseSeekCount [NumStatsKind]int
	// ForwardStepCount includes Next.
	ForwardStepCount [NumStatsKind]int
	// ReverseStepCount includes Prev.
	ReverseStepCount [NumStatsKind]int
}

var _ redact.SafeFormatter = &IteratorStats{}

// Iterator iterates over a DB's key/value pairs in key order.
//
// An iterator must be closed after use, but it is not necessary to read an
// iterator until exhaustion.
//
// An iterator is not goroutine-safe, but it is safe to use multiple iterators
// concurrently, with each in a dedicated goroutine.
//
// It is also safe to use an iterator concurrently with modifying its
// underlying DB, if that DB permits modification. However, the resultant
// key/value pairs are not guaranteed to be a consistent snapshot of that DB
// at a particular point in time.
//
// If an iterator encounters an error during any operation, it is stored by
// the Iterator and surfaced through the Error method. All absolute
// positioning methods (eg, SeekLT, SeekGT, First, Last, etc) reset any
// accumulated error before positioning. All relative positioning methods (eg,
// Next, Prev) return without advancing if the iterator has an accumulated
// error.
type Iterator struct {
	opts      IterOptions
	cmp       Compare
	equal     Equal
	merge     Merge
	split     Split
	iter      internalIterator
	readState *readState
	err       error
	// When iterValidityState=IterValid, key represents the current key, which
	// is backed by keyBuf.
	key         []byte
	keyBuf      []byte
	value       []byte
	valueBuf    []byte
	valueCloser io.Closer
	// iterKey, iterValue reflect the latest position of iter, except when
	// SetBounds is called. In that case, these are explicitly set to nil.
	iterKey             *InternalKey
	iterValue           []byte
	alloc               *iterAlloc
	getIterAlloc        *getIterAlloc
	prefixOrFullSeekKey []byte
	readSampling        readSampling
	stats               IteratorStats

	// Following fields are only used in Clone.
	// Non-nil if this Iterator includes a Batch.
	batch    *Batch
	newIters tableNewIters
	seqNum   uint64

	// Keeping the bools here after all the 8 byte aligned fields shrinks the
	// sizeof this struct by 24 bytes.

	// INVARIANT:
	// iterValidityState==IterAtLimit <=>
	//  pos==iterPosCurForwardPaused || pos==iterPosCurReversePaused
	iterValidityState IterValidityState
	// The position of iter. When this is iterPos{Prev,Next} the iter has been
	// moved past the current key-value, which can only happen if
	// iterValidityState=IterValid, i.e., there is something to return to the
	// client for the current position.
	pos iterPos
	// Relates to the prefixOrFullSeekKey field above.
	hasPrefix bool
	// Used for deriving the value of SeekPrefixGE(..., trySeekUsingNext),
	// and SeekGE/SeekLT optimizations
	lastPositioningOp lastPositioningOpKind
}

type lastPositioningOpKind int8

const (
	unknownLastPositionOp lastPositioningOpKind = iota
	seekPrefixGELastPositioningOp
	seekGELastPositioningOp
	seekLTLastPositioningOp
)

// Limited iteration mode. Not for use with prefix iteration.
//
// SeekGE, SeekLT, Prev, Next have WithLimit variants, that pause the iterator
// at the limit in a best-effort manner. The client should behave correctly
// even if the limits are ignored. These limits are not "deep", in that they
// are not passed down to the underlying collection of internalIterators. This
// is because the limits are transient, and apply only until the next
// iteration call. They serve mainly as a way to bound the amount of work when
// two (or more) Iterators are being coordinated at a higher level.
//
// In limited iteration mode:
// - Avoid using Iterator.Valid if the last call was to a *WithLimit() method.
//   The return value from the *WithLimit() method provides a more precise
//   disposition.
// - The limit is exclusive for forward and inclusive for reverse.

// IterValidityState captures the state of the Iterator.
type IterValidityState int8

const (
	// IterExhausted represents an Iterator that is exhausted.
	IterExhausted IterValidityState = iota
	// IterValid represents an Iterator that is valid.
	IterValid
	// IterAtLimit represents an Iterator that has a non-exhausted
	// internalIterator, but has reached a limit without any key for the
	// caller.
	IterAtLimit
)

// readSampling stores variables used to sample a read to trigger a read
// compaction
type readSampling struct {
	bytesUntilReadSampling uint64
	initialSamplePassed    bool
	pendingCompactions     []readCompaction
	// forceReadSampling is used for testing purposes to force a read sample on every
	// call to Iterator.maybeSampleRead()
	forceReadSampling bool
}

func (i *Iterator) findNextEntry(limit []byte) {
	i.iterValidityState = IterExhausted
	i.pos = iterPosCurForward

	// Close the closer for the current value if one was open.
	if i.valueCloser != nil {
		i.err = i.valueCloser.Close()
		i.valueCloser = nil
		if i.err != nil {
			return
		}
	}

	for i.iterKey != nil {
		key := *i.iterKey

		if i.hasPrefix {
			if n := i.split(key.UserKey); !bytes.Equal(i.prefixOrFullSeekKey, key.UserKey[:n]) {
				return
			}
		}
		// Compare with limit every time we start at a different user key.
		// Note that given the best-effort contract of limit, we could avoid a
		// comparison in the common case by doing this only after
		// i.nextUserKey is called for the deletes below. However that makes
		// the behavior non-deterministic (since the behavior will vary based
		// on what has been compacted), which makes it hard to test with the
		// metamorphic test. So we forego that performance optimization.
		if limit != nil && i.cmp(limit, i.iterKey.UserKey) <= 0 {
			i.iterValidityState = IterAtLimit
			i.pos = iterPosCurForwardPaused
			return
		}

		switch key.Kind() {
		case InternalKeyKindDelete, InternalKeyKindSingleDelete:
			i.nextUserKey()
			continue

		case InternalKeyKindSet:
			i.keyBuf = append(i.keyBuf[:0], key.UserKey...)
			i.key = i.keyBuf
			i.value = i.iterValue
			i.iterValidityState = IterValid
			return

		case InternalKeyKindMerge:
			var valueMerger ValueMerger
			valueMerger, i.err = i.merge(i.key, i.iterValue)
			if i.err == nil {
				i.mergeNext(key, valueMerger)
			}
			if i.err == nil {
				i.value, i.valueCloser, i.err = valueMerger.Finish(true /* includesBase */)
			} else {
				// mergeNext may have been called, which can set
				// i.iterValidityState=IterValid.
				i.iterValidityState = IterExhausted
			}
			return

		default:
			i.err = base.CorruptionErrorf("pebble: invalid internal key kind: %d", errors.Safe(key.Kind()))
			i.iterValidityState = IterExhausted
			return
		}
	}
}

func (i *Iterator) nextUserKey() {
	if i.iterKey == nil {
		return
	}
	done := i.iterKey.SeqNum() == 0
	if i.iterValidityState != IterValid {
		i.keyBuf = append(i.keyBuf[:0], i.iterKey.UserKey...)
		i.key = i.keyBuf
	}
	for {
		i.iterKey, i.iterValue = i.iter.Next()
		i.stats.ForwardStepCount[InternalIterCall]++
		if done || i.iterKey == nil {
			break
		}
		if !i.equal(i.key, i.iterKey.UserKey) {
			break
		}
		done = i.iterKey.SeqNum() == 0
	}
}

func (i *Iterator) maybeSampleRead() {
	// This method is only called when a public method of Iterator is
	// returning, and below we exclude the case were the iterator is paused at
	// a limit. The effect of these choices is that keys that are deleted, but
	// are encountered during iteration, are not accounted for in the read
	// sampling and will not cause read driven compactions, even though we are
	// incurring cost in iterating over them. And this issue is not limited to
	// Iterator, which does not see the effect of range deletes, which may be
	// causing iteration work in mergingIter. It is not clear at this time
	// whether this is a deficiency worth addressing.
	if i.iterValidityState != IterValid {
		return
	}
	if i.readState == nil {
		return
	}
	if i.readSampling.forceReadSampling {
		i.sampleRead()
		return
	}
	samplingPeriod := int32(int64(readBytesPeriod) * i.readState.db.opts.Experimental.ReadSamplingMultiplier)
	if samplingPeriod <= 0 {
		return
	}
	bytesRead := uint64(len(i.key) + len(i.value))
	for i.readSampling.bytesUntilReadSampling < bytesRead {
		i.readSampling.bytesUntilReadSampling += uint64(fastrand.Uint32n(2 * uint32(samplingPeriod)))
		// The block below tries to adjust for the case where this is the
		// first read in a newly-opened iterator. As bytesUntilReadSampling
		// starts off at zero, we don't want to sample the first read of
		// every newly-opened iterator, but we do want to sample some of them.
		if !i.readSampling.initialSamplePassed {
			i.readSampling.initialSamplePassed = true
			if fastrand.Uint32n(uint32(i.readSampling.bytesUntilReadSampling)) > uint32(bytesRead) {
				continue
			}
		}
		i.sampleRead()
	}
	i.readSampling.bytesUntilReadSampling -= bytesRead
}

func (i *Iterator) sampleRead() {
	var topFile *manifest.FileMetadata
	topLevel, numOverlappingLevels := numLevels, 0
	if mi, ok := i.iter.(*mergingIter); ok {
		if len(mi.levels) > 1 {
			mi.ForEachLevelIter(func(li *levelIter) bool {
				l := manifest.LevelToInt(li.level)
				if file := li.files.Current(); file != nil {
					var containsKey bool
					if i.pos == iterPosNext || i.pos == iterPosCurForward ||
						i.pos == iterPosCurForwardPaused {
						containsKey = i.cmp(file.Smallest.UserKey, i.key) <= 0
					} else if i.pos == iterPosPrev || i.pos == iterPosCurReverse ||
						i.pos == iterPosCurReversePaused {
						containsKey = i.cmp(file.Largest.UserKey, i.key) >= 0
					}
					// Do nothing if the current key is not contained in file's
					// bounds. We could seek the LevelIterator at this level
					// to find the right file, but the performance impacts of
					// doing that are significant enough to negate the benefits
					// of read sampling in the first place. See the discussion
					// at:
					// https://github.com/cockroachdb/pebble/pull/1041#issuecomment-763226492
					if containsKey {
						numOverlappingLevels++
						if numOverlappingLevels >= 2 {
							// Terminate the loop early if at least 2 overlapping levels are found.
							return true
						}
						topLevel = l
						topFile = file
					}
				}
				return false
			})
		}
	}
	if topFile == nil || topLevel >= numLevels {
		return
	}
	if numOverlappingLevels >= 2 {
		allowedSeeks := atomic.AddInt64(&topFile.Atomic.AllowedSeeks, -1)
		if allowedSeeks == 0 {
			read := readCompaction{
				start: topFile.Smallest.UserKey,
				end:   topFile.Largest.UserKey,
				level: topLevel,
			}
			i.readSampling.pendingCompactions = append(i.readSampling.pendingCompactions, read)
		}
	}
}

func (i *Iterator) findPrevEntry(limit []byte) {
	i.iterValidityState = IterExhausted
	i.pos = iterPosCurReverse

	// Close the closer for the current value if one was open.
	if i.valueCloser != nil {
		i.err = i.valueCloser.Close()
		i.valueCloser = nil
		if i.err != nil {
			i.iterValidityState = IterExhausted
			return
		}
	}

	var valueMerger ValueMerger
	firstLoopIter := true
	// The code below compares with limit in multiple places. As documented in
	// findNextEntry, this is being done to make the behavior of limit
	// deterministic to allow for metamorphic testing. It is not required by
	// the best-effort contract of limit.
	for i.iterKey != nil {
		key := *i.iterKey

		if firstLoopIter && limit != nil && i.cmp(limit, i.iterKey.UserKey) > 0 {
			i.iterValidityState = IterAtLimit
			i.pos = iterPosCurReversePaused
			return
		}
		firstLoopIter = false

		if i.iterValidityState == IterValid {
			if !i.equal(key.UserKey, i.key) {
				// We've iterated to the previous user key.
				i.pos = iterPosPrev
				if valueMerger != nil {
					i.value, i.valueCloser, i.err = valueMerger.Finish(true /* includesBase */)
				}
				if i.err != nil {
					i.iterValidityState = IterExhausted
				}
				return
			}
		}

		switch key.Kind() {
		case InternalKeyKindDelete, InternalKeyKindSingleDelete:
			i.value = nil
			i.iterValidityState = IterExhausted
			valueMerger = nil
			i.iterKey, i.iterValue = i.iter.Prev()
			i.stats.ReverseStepCount[InternalIterCall]++
			// Compare with the limit. We could optimize by only checking when
			// we step to the previous user key, but detecting that requires a
			// comparison too. Note that this position may already passed a
			// number of versions of this user key, but they are all deleted,
			// so the fact that a subsequent Prev*() call will not see them is
			// harmless. Also note that this is the only place in the loop,
			// other than the firstLoopIter case above, where we could step
			// to a different user key and start processing it for returning
			// to the caller.
			if limit != nil && i.iterKey != nil && i.cmp(limit, i.iterKey.UserKey) > 0 {
				i.iterValidityState = IterAtLimit
				i.pos = iterPosCurReversePaused
				return
			}
			continue

		case InternalKeyKindSet:
			i.keyBuf = append(i.keyBuf[:0], key.UserKey...)
			i.key = i.keyBuf
			// iterValue is owned by i.iter and could change after the Prev()
			// call, so use valueBuf instead. Note that valueBuf is only used
			// in this one instance; everywhere else (eg. in findNextEntry),
			// we just point i.value to the unsafe i.iter-owned value buffer.
			i.valueBuf = append(i.valueBuf[:0], i.iterValue...)
			i.value = i.valueBuf
			i.iterValidityState = IterValid
			i.iterKey, i.iterValue = i.iter.Prev()
			i.stats.ReverseStepCount[InternalIterCall]++
			valueMerger = nil
			continue

		case InternalKeyKindMerge:
			if i.iterValidityState == IterExhausted {
				i.keyBuf = append(i.keyBuf[:0], key.UserKey...)
				i.key = i.keyBuf
				valueMerger, i.err = i.merge(i.key, i.iterValue)
				if i.err != nil {
					return
				}
				i.iterValidityState = IterValid
			} else if valueMerger == nil {
				valueMerger, i.err = i.merge(i.key, i.value)
				if i.err == nil {
					i.err = valueMerger.MergeNewer(i.iterValue)
				}
				if i.err != nil {
					i.iterValidityState = IterExhausted
					return
				}
			} else {
				i.err = valueMerger.MergeNewer(i.iterValue)
				if i.err != nil {
					i.iterValidityState = IterExhausted
					return
				}
			}
			i.iterKey, i.iterValue = i.iter.Prev()
			i.stats.ReverseStepCount[InternalIterCall]++
			continue

		default:
			i.err = base.CorruptionErrorf("pebble: invalid internal key kind: %d", errors.Safe(key.Kind()))
			i.iterValidityState = IterExhausted
			return
		}
	}

	// i.iterKey == nil, so broke out of the preceding loop.
	if i.iterValidityState == IterValid {
		i.pos = iterPosPrev
		if valueMerger != nil {
			i.value, i.valueCloser, i.err = valueMerger.Finish(true /* includesBase */)
		}
		if i.err != nil {
			i.iterValidityState = IterExhausted
		}
	}
}

func (i *Iterator) prevUserKey() {
	if i.iterKey == nil {
		return
	}
	if i.iterValidityState != IterValid {
		// If we're going to compare against the prev key, we need to save the
		// current key.
		i.keyBuf = append(i.keyBuf[:0], i.iterKey.UserKey...)
		i.key = i.keyBuf
	}
	for {
		i.iterKey, i.iterValue = i.iter.Prev()
		i.stats.ReverseStepCount[InternalIterCall]++
		if i.iterKey == nil {
			break
		}
		if !i.equal(i.key, i.iterKey.UserKey) {
			break
		}
	}
}

func (i *Iterator) mergeNext(key InternalKey, valueMerger ValueMerger) {
	// Save the current key.
	i.keyBuf = append(i.keyBuf[:0], key.UserKey...)
	i.key = i.keyBuf
	i.iterValidityState = IterValid

	// Loop looking for older values for this key and merging them.
	for {
		i.iterKey, i.iterValue = i.iter.Next()
		i.stats.ForwardStepCount[InternalIterCall]++
		if i.iterKey == nil {
			i.pos = iterPosNext
			return
		}
		key = *i.iterKey
		if !i.equal(i.key, key.UserKey) {
			// We've advanced to the next key.
			i.pos = iterPosNext
			return
		}
		switch key.Kind() {
		case InternalKeyKindDelete, InternalKeyKindSingleDelete:
			// We've hit a deletion tombstone. Return everything up to this
			// point.
			return

		case InternalKeyKindSet:
			// We've hit a Set value. Merge with the existing value and return.
			i.err = valueMerger.MergeOlder(i.iterValue)
			return

		case InternalKeyKindMerge:
			// We've hit another Merge value. Merge with the existing value and
			// continue looping.
			i.err = valueMerger.MergeOlder(i.iterValue)
			if i.err != nil {
				return
			}
			continue

		default:
			i.err = base.CorruptionErrorf("pebble: invalid internal key kind: %d", errors.Safe(key.Kind()))
			return
		}
	}
}

// SeekGE moves the iterator to the first key/value pair whose key is greater
// than or equal to the given key. Returns true if the iterator is pointing at
// a valid entry and false otherwise.
func (i *Iterator) SeekGE(key []byte) bool {
	return i.SeekGEWithLimit(key, nil) == IterValid
}

// SeekGEWithLimit ...
func (i *Iterator) SeekGEWithLimit(key []byte, limit []byte) IterValidityState {
	lastPositioningOp := i.lastPositioningOp
	// Set it to unknown, since this operation may not succeed, in which case
	// the SeekGE following this should not make any assumption about iterator
	// position.
	i.lastPositioningOp = unknownLastPositionOp
	i.err = nil // clear cached iteration error
	i.hasPrefix = false
	i.stats.ForwardSeekCount[InterfaceCall]++
	if lowerBound := i.opts.GetLowerBound(); lowerBound != nil && i.cmp(key, lowerBound) < 0 {
		key = lowerBound
	} else if upperBound := i.opts.GetUpperBound(); upperBound != nil && i.cmp(key, upperBound) > 0 {
		key = upperBound
	}
	seekInternalIter := true
	// The following noop optimization only applies when i.batch == nil, since
	// an iterator over a batch is iterating over mutable data, that may have
	// changed since the last seek.
	if lastPositioningOp == seekGELastPositioningOp && i.batch == nil {
		cmp := i.cmp(i.prefixOrFullSeekKey, key)
		// If this seek is to the same or later key, and the iterator is
		// already positioned there, this is a noop. This can be helpful for
		// sparse key spaces that have many deleted keys, where one can avoid
		// the overhead of iterating past them again and again.
		if cmp <= 0 {
			if i.iterValidityState == IterExhausted ||
				(i.iterValidityState == IterValid && i.cmp(key, i.key) <= 0 &&
					(limit == nil || i.cmp(i.key, limit) < 0)) {
				// Noop
				if !invariants.Enabled || !disableSeekOpt(key, uintptr(unsafe.Pointer(i))) {
					i.lastPositioningOp = seekGELastPositioningOp
					return i.iterValidityState
				}
			}
			if i.pos == iterPosCurForwardPaused && i.cmp(key, i.iterKey.UserKey) <= 0 {
				// Have some work to do, but don't need to seek, and we can
				// start doing findNextEntry from i.iterKey.
				seekInternalIter = false
			}
		}
	}
	if seekInternalIter {
		i.iterKey, i.iterValue = i.iter.SeekGE(key)
		i.stats.ForwardSeekCount[InternalIterCall]++
	}
	i.findNextEntry(limit)
	i.maybeSampleRead()
	if i.Error() == nil && i.batch == nil {
		// Prepare state for a future noop optimization.
		i.prefixOrFullSeekKey = append(i.prefixOrFullSeekKey[:0], key...)
		i.lastPositioningOp = seekGELastPositioningOp
	}
	return i.iterValidityState
}

// SeekPrefixGE moves the iterator to the first key/value pair whose key is
// greater than or equal to the given key and which has the same "prefix" as
// the given key. The prefix for a key is determined by the user-defined
// Comparer.Split function. The iterator will not observe keys not matching the
// "prefix" of the search key. Calling SeekPrefixGE puts the iterator in prefix
// iteration mode. The iterator remains in prefix iteration until a subsequent
// call to another absolute positioning method (SeekGE, SeekLT, First,
// Last). Reverse iteration (Prev) is not supported when an iterator is in
// prefix iteration mode. Returns true if the iterator is pointing at a valid
// entry and false otherwise.
//
// The semantics of SeekPrefixGE are slightly unusual and designed for
// iteration to be able to take advantage of bloom filters that have been
// created on the "prefix". If you're not using bloom filters, there is no
// reason to use SeekPrefixGE.
//
// An example Split function may separate a timestamp suffix from the prefix of
// the key.
//
//   Split(<key>@<timestamp>) -> <key>
//
// Consider the keys "a@1", "a@2", "aa@3", "aa@4". The prefixes for these keys
// are "a", and "aa". Note that despite "a" and "aa" sharing a prefix by the
// usual definition, those prefixes differ by the definition of the Split
// function. To see how this works, consider the following set of calls on this
// data set:
//
//   SeekPrefixGE("a@0") -> "a@1"
//   Next()              -> "a@2"
//   Next()              -> EOF
//
// If you're just looking to iterate over keys with a shared prefix, as
// defined by the configured comparer, set iterator bounds instead:
//
//  iter := db.NewIter(&pebble.IterOptions{
//    LowerBound: []byte("prefix"),
//    UpperBound: []byte("prefiy"),
//  })
//  for iter.First(); iter.Valid(); iter.Next() {
//    // Only keys beginning with "prefix" will be visited.
//  }
//
// See ExampleIterator_SeekPrefixGE for a working example.
func (i *Iterator) SeekPrefixGE(key []byte) bool {
	lastPositioningOp := i.lastPositioningOp
	// Set it to unknown, since this operation may not succeed, in which case
	// the SeekPrefixGE following this should not make any assumption about
	// iterator position.
	i.lastPositioningOp = unknownLastPositionOp
	i.err = nil // clear cached iteration error
	i.stats.ForwardSeekCount[InterfaceCall]++

	if i.split == nil {
		panic("pebble: split must be provided for SeekPrefixGE")
	}

	prefixLen := i.split(key)
	keyPrefix := key[:prefixLen]
	trySeekUsingNext := false
	if lastPositioningOp == seekPrefixGELastPositioningOp {
		if !i.hasPrefix {
			panic("lastPositioningOpsIsSeekPrefixGE is true, but hasPrefix is false")
		}
		// The iterator has not been repositioned after the last SeekPrefixGE.
		// See if we are seeking to a larger key, since then we can optimize
		// the seek by using next. Note that we could also optimize if Next
		// has been called, if the iterator is not exhausted and the current
		// position is <= the seek key. We are keeping this limited for now
		// since such optimizations require care for correctness, and to not
		// become de-optimizations (if one usually has to do all the next
		// calls and then the seek). This SeekPrefixGE optimization
		// specifically benefits CockroachDB.
		cmp := i.cmp(i.prefixOrFullSeekKey, keyPrefix)
		// cmp == 0 is not safe to optimize since
		// - i.pos could be at iterPosNext, due to a merge.
		// - Even if i.pos were at iterPosCurForward, we could have a DELETE,
		//   SET pair for a key, and the iterator would have moved past DELETE
		//   but stayed at iterPosCurForward. A similar situation occurs for a
		//   MERGE, SET pair where the MERGE is consumed and the iterator is
		//   at the SET.
		// In general some versions of i.prefix could have been consumed by
		// the iterator, so we only optimize for cmp < 0.
		trySeekUsingNext = cmp < 0
		if invariants.Enabled && trySeekUsingNext && disableSeekOpt(key, uintptr(unsafe.Pointer(i))) {
			trySeekUsingNext = false
		}
	}
	// Make a copy of the prefix so that modifications to the key after
	// SeekPrefixGE returns does not affect the stored prefix.
	if cap(i.prefixOrFullSeekKey) < prefixLen {
		i.prefixOrFullSeekKey = make([]byte, prefixLen)
	} else {
		i.prefixOrFullSeekKey = i.prefixOrFullSeekKey[:prefixLen]
	}
	i.hasPrefix = true
	copy(i.prefixOrFullSeekKey, keyPrefix)

	if lowerBound := i.opts.GetLowerBound(); lowerBound != nil && i.cmp(key, lowerBound) < 0 {
		if n := i.split(lowerBound); !bytes.Equal(i.prefixOrFullSeekKey, lowerBound[:n]) {
			i.err = errors.New("pebble: SeekPrefixGE supplied with key outside of lower bound")
			return false
		}
		key = lowerBound
	} else if upperBound := i.opts.GetUpperBound(); upperBound != nil && i.cmp(key, upperBound) > 0 {
		if n := i.split(upperBound); !bytes.Equal(i.prefixOrFullSeekKey, upperBound[:n]) {
			i.err = errors.New("pebble: SeekPrefixGE supplied with key outside of upper bound")
			return false
		}
		key = upperBound
	}

	i.iterKey, i.iterValue = i.iter.SeekPrefixGE(i.prefixOrFullSeekKey, key, trySeekUsingNext)
	i.stats.ForwardSeekCount[InternalIterCall]++
	i.findNextEntry(nil)
	i.maybeSampleRead()
	if i.Error() == nil {
		i.lastPositioningOp = seekPrefixGELastPositioningOp
	}
	return i.iterValidityState == IterValid
}

// Deterministic disabling of the seek optimization. It uses the iterator
// pointer, since we want diversity in iterator behavior for the same key.
// Used for tests.
func disableSeekOpt(key []byte, ptr uintptr) bool {
	// Fibonacci hash https://probablydance.com/2018/06/16/fibonacci-hashing-the-optimization-that-the-world-forgot-or-a-better-alternative-to-integer-modulo/
	simpleHash := (11400714819323198485 * uint64(ptr)) >> 63
	return key != nil && key[0]&byte(1) == 0 && simpleHash == 0
}

// SeekLT moves the iterator to the last key/value pair whose key is less than
// the given key. Returns true if the iterator is pointing at a valid entry and
// false otherwise.
func (i *Iterator) SeekLT(key []byte) bool {
	return i.SeekLTWithLimit(key, nil) == IterValid
}

// SeekLTWithLimit ...
func (i *Iterator) SeekLTWithLimit(key []byte, limit []byte) IterValidityState {
	lastPositioningOp := i.lastPositioningOp
	// Set it to unknown, since this operation may not succeed, in which case
	// the SeekLT following this should not make any assumption about iterator
	// position.
	i.lastPositioningOp = unknownLastPositionOp
	i.err = nil // clear cached iteration error
	i.hasPrefix = false
	i.stats.ReverseSeekCount[InterfaceCall]++
	if upperBound := i.opts.GetUpperBound(); upperBound != nil && i.cmp(key, upperBound) > 0 {
		key = upperBound
	} else if lowerBound := i.opts.GetLowerBound(); lowerBound != nil && i.cmp(key, lowerBound) < 0 {
		key = lowerBound
	}
	seekInternalIter := true
	// The following noop optimization only applies when i.batch == nil, since
	// an iterator over a batch is iterating over mutable data, that may have
	// changed since the last seek.
	if lastPositioningOp == seekLTLastPositioningOp && i.batch == nil {
		cmp := i.cmp(key, i.prefixOrFullSeekKey)
		// If this seek is to the same or earlier key, and the iterator is
		// already positioned there, this is a noop. This can be helpful for
		// sparse key spaces that have many deleted keys, where one can avoid
		// the overhead of iterating past them again and again.
		if cmp <= 0 {
			// NB: when pos != iterPosCurReversePaused, the invariant
			// documented earlier implies that iterValidityState !=
			// IterAtLimit.
			if i.iterValidityState == IterExhausted ||
				(i.iterValidityState == IterValid && i.cmp(i.key, key) < 0 &&
					(limit == nil || i.cmp(limit, i.key) <= 0)) {
				if !invariants.Enabled || !disableSeekOpt(key, uintptr(unsafe.Pointer(i))) {
					i.lastPositioningOp = seekLTLastPositioningOp
					return i.iterValidityState
				}
			}
			if i.pos == iterPosCurReversePaused && i.cmp(i.iterKey.UserKey, key) < 0 {
				// Have some work to do, but don't need to seek, and we can
				// start doing findPrevEntry from i.iterKey.
				seekInternalIter = false
			}
		}
	}
	if seekInternalIter {
		i.iterKey, i.iterValue = i.iter.SeekLT(key)
		i.stats.ReverseSeekCount[InternalIterCall]++
	}
	i.findPrevEntry(limit)
	i.maybeSampleRead()
	if i.Error() == nil && i.batch == nil {
		// Prepare state for a future noop optimization.
		i.prefixOrFullSeekKey = append(i.prefixOrFullSeekKey[:0], key...)
		i.lastPositioningOp = seekLTLastPositioningOp
	}
	return i.iterValidityState
}

// First moves the iterator the the first key/value pair. Returns true if the
// iterator is pointing at a valid entry and false otherwise.
func (i *Iterator) First() bool {
	i.err = nil // clear cached iteration error
	i.hasPrefix = false
	i.lastPositioningOp = unknownLastPositionOp
	i.stats.ForwardSeekCount[InterfaceCall]++
	if lowerBound := i.opts.GetLowerBound(); lowerBound != nil {
		i.iterKey, i.iterValue = i.iter.SeekGE(lowerBound)
		i.stats.ForwardSeekCount[InternalIterCall]++
	} else {
		i.iterKey, i.iterValue = i.iter.First()
		i.stats.ForwardSeekCount[InternalIterCall]++
	}
	i.findNextEntry(nil)
	i.maybeSampleRead()
	return i.iterValidityState == IterValid
}

// Last moves the iterator the the last key/value pair. Returns true if the
// iterator is pointing at a valid entry and false otherwise.
func (i *Iterator) Last() bool {
	i.err = nil // clear cached iteration error
	i.hasPrefix = false
	i.lastPositioningOp = unknownLastPositionOp
	i.stats.ReverseSeekCount[InterfaceCall]++
	if upperBound := i.opts.GetUpperBound(); upperBound != nil {
		i.iterKey, i.iterValue = i.iter.SeekLT(upperBound)
		i.stats.ReverseSeekCount[InternalIterCall]++
	} else {
		i.iterKey, i.iterValue = i.iter.Last()
		i.stats.ReverseSeekCount[InternalIterCall]++
	}
	i.findPrevEntry(nil)
	i.maybeSampleRead()
	return i.iterValidityState == IterValid
}

// Next moves the iterator to the next key/value pair. Returns true if the
// iterator is pointing at a valid entry and false otherwise.
func (i *Iterator) Next() bool {
	return i.NextWithLimit(nil) == IterValid
}

// NextWithLimit ...
func (i *Iterator) NextWithLimit(limit []byte) IterValidityState {
	i.stats.ForwardStepCount[InterfaceCall]++
	if limit != nil && i.hasPrefix {
		i.err = errors.New("cannot use limit with prefix iteration")
		i.iterValidityState = IterExhausted
		return i.iterValidityState
	}
	if i.err != nil {
		return i.iterValidityState
	}
	i.lastPositioningOp = unknownLastPositionOp
	switch i.pos {
	case iterPosCurForward:
		i.nextUserKey()
	case iterPosCurForwardPaused:
		// Already at the right place.
	case iterPosCurReverse:
		// Switching directions.
		// Unless the iterator was exhausted, reverse iteration needs to
		// position the iterator at iterPosPrev.
		if i.iterKey != nil {
			i.err = errors.New("switching from reverse to forward but iter is not at prev")
			i.iterValidityState = IterExhausted
			return i.iterValidityState
		}
		// We're positioned before the first key. Need to reposition to point to
		// the first key.
		if lowerBound := i.opts.GetLowerBound(); lowerBound != nil {
			i.iterKey, i.iterValue = i.iter.SeekGE(lowerBound)
			i.stats.ForwardSeekCount[InternalIterCall]++
		} else {
			i.iterKey, i.iterValue = i.iter.First()
			i.stats.ForwardSeekCount[InternalIterCall]++
		}
	case iterPosCurReversePaused:
		// Switching directions.
		// The iterator must not be exhausted since it paused.
		if i.iterKey == nil {
			i.err = errors.New("switching paused from reverse to forward but iter is exhausted")
			i.iterValidityState = IterExhausted
			return i.iterValidityState
		}
		i.nextUserKey()
	case iterPosPrev:
		// The underlying iterator is pointed to the previous key (this can
		// only happen when switching iteration directions). We set
		// i.iterValidityState to IterExhausted here to force the calls to
		// nextUserKey to save the current key i.iter is pointing at in order
		// to determine when the next user-key is reached.
		i.iterValidityState = IterExhausted
		if i.iterKey == nil {
			// We're positioned before the first key. Need to reposition to point to
			// the first key.
			if lowerBound := i.opts.GetLowerBound(); lowerBound != nil {
				i.iterKey, i.iterValue = i.iter.SeekGE(lowerBound)
				i.stats.ForwardSeekCount[InternalIterCall]++
			} else {
				i.iterKey, i.iterValue = i.iter.First()
				i.stats.ForwardSeekCount[InternalIterCall]++
			}
		} else {
			i.nextUserKey()
		}
		i.nextUserKey()
	case iterPosNext:
		// Already at the right place.
	}
	i.findNextEntry(limit)
	i.maybeSampleRead()
	return i.iterValidityState
}

// Prev moves the iterator to the previous key/value pair. Returns true if the
// iterator is pointing at a valid entry and false otherwise.
func (i *Iterator) Prev() bool {
	return i.PrevWithLimit(nil) == IterValid
}

// PrevWithLimit ...
func (i *Iterator) PrevWithLimit(limit []byte) IterValidityState {
	i.stats.ReverseStepCount[InterfaceCall]++
	if i.err != nil {
		return i.iterValidityState
	}
	i.lastPositioningOp = unknownLastPositionOp
	if i.hasPrefix {
		i.err = errReversePrefixIteration
		i.iterValidityState = IterExhausted
		return i.iterValidityState
	}
	switch i.pos {
	case iterPosCurForward:
		// Switching directions, and will handle this below.
	case iterPosCurForwardPaused:
		// Switching directions, and will handle this below.
	case iterPosCurReverse:
		i.prevUserKey()
	case iterPosCurReversePaused:
		// Already at the right place.
	case iterPosNext:
		// The underlying iterator is pointed to the next key (this can only happen
		// when switching iteration directions). We will handle this below.
	case iterPosPrev:
		// Already at the right place.
	}
	if i.pos == iterPosCurForward || i.pos == iterPosNext || i.pos == iterPosCurForwardPaused {
		stepAgain := i.pos == iterPosNext
		// Switching direction.
		// We set i.iterValidityState to IterExhausted here to force the calls
		// to prevUserKey to save the current key i.iter is pointing at in
		// order to determine when the prev user-key is reached.
		i.iterValidityState = IterExhausted
		if i.iterKey == nil {
			// We're positioned after the last key. Need to reposition to point to
			// the last key.
			if upperBound := i.opts.GetUpperBound(); upperBound != nil {
				i.iterKey, i.iterValue = i.iter.SeekLT(upperBound)
				i.stats.ReverseSeekCount[InternalIterCall]++
			} else {
				i.iterKey, i.iterValue = i.iter.Last()
				i.stats.ReverseSeekCount[InternalIterCall]++
			}
		} else {
			i.prevUserKey()
		}
		if stepAgain {
			i.prevUserKey()
		}
	}
	i.findPrevEntry(limit)
	i.maybeSampleRead()
	return i.iterValidityState
}

// Key returns the key of the current key/value pair, or nil if done. The
// caller should not modify the contents of the returned slice, and its
// contents may change on the next call to Next.
func (i *Iterator) Key() []byte {
	return i.key
}

// Value returns the value of the current key/value pair, or nil if done. The
// caller should not modify the contents of the returned slice, and its
// contents may change on the next call to Next.
func (i *Iterator) Value() []byte {
	return i.value
}

// Valid returns true if the iterator is positioned at a valid key/value pair
// and false otherwise.
func (i *Iterator) Valid() bool {
	return i.iterValidityState == IterValid
}

// Error returns any accumulated error.
func (i *Iterator) Error() error {
	err := i.err
	if i.iter != nil {
		err = firstError(i.err, i.iter.Error())
	}
	return err
}

// Close closes the iterator and returns any accumulated error. Exhausting
// all the key/value pairs in a table is not considered to be an error.
// It is not valid to call any method, including Close, after the iterator
// has been closed.
func (i *Iterator) Close() error {
	// Close the child iterator before releasing the readState because when the
	// readState is released sstables referenced by the readState may be deleted
	// which will fail on Windows if the sstables are still open by the child
	// iterator.
	if i.iter != nil {
		i.err = firstError(i.err, i.iter.Close())
	}
	err := i.err

	if i.readState != nil {
		if len(i.readSampling.pendingCompactions) > 0 {
			// Copy pending read compactions using db.mu.Lock()
			i.readState.db.mu.Lock()
			i.readState.db.mu.compact.readCompactions = append(i.readState.db.mu.compact.readCompactions, i.readSampling.pendingCompactions...)
			i.readState.db.mu.Unlock()
		}

		i.readState.unref()
		i.readState = nil
	}

	// Close the closer for the current value if one was open.
	if i.valueCloser != nil {
		err = firstError(err, i.valueCloser.Close())
		i.valueCloser = nil
	}

	const maxKeyBufCacheSize = 4 << 10 // 4 KB

	if alloc := i.alloc; alloc != nil {
		// Avoid caching the key buf if it is overly large. The constant is fairly
		// arbitrary.
		if cap(i.keyBuf) >= maxKeyBufCacheSize {
			alloc.keyBuf = nil
		} else {
			alloc.keyBuf = i.keyBuf
		}
		if cap(i.prefixOrFullSeekKey) >= maxKeyBufCacheSize {
			alloc.prefixOrFullSeekKey = nil
		} else {
			alloc.prefixOrFullSeekKey = i.prefixOrFullSeekKey
		}
		*i = Iterator{}
		iterAllocPool.Put(alloc)
	} else if alloc := i.getIterAlloc; alloc != nil {
		if cap(i.keyBuf) >= maxKeyBufCacheSize {
			alloc.keyBuf = nil
		} else {
			alloc.keyBuf = i.keyBuf
		}
		*i = Iterator{}
		getIterAllocPool.Put(alloc)
	}
	return err
}

// SetBounds sets the lower and upper bounds for the iterator. Note that:
// - The slices provided in this SetBounds must not be changed by the caller
//   until the iterator is closed, or a subsequent SetBounds has returned.
//   This is because comparisons between the existing and new bounds are
//   sometimes used to optimize seeking.
// - If the bounds are not changing from the existing ones, it would be
//   worthwhile for the caller to avoid calling SetBounds, since that allows
//   for more seek optimizations. Note that the callee cannot itself look to
//   see if the bounds are not changing and ignore the call, since the caller
//   may then start mutating the underlying slices. Specifically, consider
//   SetBounds(l1, u1), SetBounds(l2, u2) where l1=l2 and u1=u2. The callee
//   cannot ignore the second call and keep using l1, u1, since the contract
//   with the caller allows the caller to mutate l1, u1 after the second call
//   returns, as mentioned in the previous bullet (ignoring in the callee
//   resulted in a hard to find bug).
// - The iterator will always be invalidated and must be repositioned with a
//   call to SeekGE, SeekPrefixGE, SeekLT, First, or Last.
func (i *Iterator) SetBounds(lower, upper []byte) {
	// Even though this is not a positioning operation, the alteration of the
	// bounds means we cannot optimize Seeks by using Next.
	i.lastPositioningOp = unknownLastPositionOp
	i.hasPrefix = false
	i.iterKey = nil
	i.iterValue = nil
	// This switch statement isn't necessary for correctness since callers
	// should call a repositioning method. We could have arbitrarily set i.pos
	// to one of the values. But it results in more intuitive behavior in
	// tests, which do not always reposition.
	switch i.pos {
	case iterPosCurForward, iterPosNext, iterPosCurForwardPaused:
		i.pos = iterPosCurForward
	case iterPosCurReverse, iterPosPrev, iterPosCurReversePaused:
		i.pos = iterPosCurReverse
	}
	i.iterValidityState = IterExhausted

	i.opts.LowerBound = lower
	i.opts.UpperBound = upper
	i.iter.SetBounds(lower, upper)
}

// Metrics returns per-iterator metrics.
func (i *Iterator) Metrics() IteratorMetrics {
	m := IteratorMetrics{
		ReadAmp: 1,
	}
	if mi, ok := i.iter.(*mergingIter); ok {
		m.ReadAmp = len(mi.levels)
	}
	return m
}

// ResetStats resets the stats to 0.
func (i *Iterator) ResetStats() {
	i.stats = IteratorStats{}
}

// Stats returns the current stats.
func (i *Iterator) Stats() IteratorStats {
	return i.stats
}

// Clone creates a new Iterator over the same underlying data, i.e., over the
// same {batch, memtables, sstables}). It starts with the same IterOptions but
// is not positioned. Note that IterOptions is not deep-copied, so the
// LowerBound and UpperBound slices will share memory with the original
// Iterator. Iterators assume that these bound slices are not mutated by the
// callers, for the lifetime of use by an Iterator. The lifetime of use spans
// from the Iterator creation/SetBounds call to the next SetBounds call. If
// the caller is tracking this lifetime in order to reuse memory of these
// slices, it must remember that now the lifetime of use is due to multiple
// Iterators. The simplest behavior the caller can adopt to decouple lifetimes
// is to call SetBounds on the new Iterator, immediately after Clone returns,
// with different bounds slices.
//
// Callers can use Clone if they need multiple iterators that need to see
// exactly the same underlying state of the DB. This should not be used to
// extend the lifetime of the data backing the original Iterator since that
// will cause an increase in memory and disk usage (use NewSnapshot for that
// purpose).
func (i *Iterator) Clone() (*Iterator, error) {
	readState := i.readState
	if readState == nil {
		return nil, errors.Errorf("cannot Clone a closed Iterator")
	}
	// i is already holding a ref, so there is no race with unref here.
	readState.ref()
	// Bundle various structures under a single umbrella in order to allocate
	// them together.
	buf := iterAllocPool.Get().(*iterAlloc)
	dbi := &buf.dbi
	*dbi = Iterator{
		opts:                i.opts,
		alloc:               buf,
		cmp:                 i.cmp,
		equal:               i.equal,
		iter:                &buf.merging,
		merge:               i.merge,
		split:               i.split,
		readState:           readState,
		keyBuf:              buf.keyBuf,
		prefixOrFullSeekKey: buf.prefixOrFullSeekKey,
		batch:               i.batch,
		newIters:            i.newIters,
		seqNum:              i.seqNum,
	}
	return finishInitializingIter(buf), nil
}

func (stats *IteratorStats) String() string {
	return redact.StringWithoutMarkers(stats)
}

// SafeFormat implements the redact.SafeFormatter interface.
func (stats *IteratorStats) SafeFormat(s redact.SafePrinter, verb rune) {
	for i := range stats.ForwardStepCount {
		switch IteratorStatsKind(i) {
		case InterfaceCall: s.SafeString("(interface (dir, seek, step): ")
		case InternalIterCall: s.SafeString(", (internal (dir, seek, step): ")
		}
		s.Printf("(fwd, %d, %d), (rev, %d, %d))",
			redact.Safe(stats.ForwardSeekCount[i]), redact.Safe(stats.ForwardStepCount[i]),
			redact.Safe(stats.ReverseSeekCount[i]), redact.Safe(stats.ReverseStepCount[i]))
	}
}
