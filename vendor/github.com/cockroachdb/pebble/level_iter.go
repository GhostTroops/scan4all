// Copyright 2018 The LevelDB-Go and Pebble Authors. All rights reserved. Use
// of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package pebble

import (
	"fmt"
	"runtime/debug"

	"github.com/cockroachdb/pebble/internal/base"
	"github.com/cockroachdb/pebble/internal/invariants"
	"github.com/cockroachdb/pebble/internal/manifest"
)

// tableNewIters creates a new point and range-del iterator for the given file
// number. If bytesIterated is specified, it is incremented as the given file is
// iterated through.
type tableNewIters func(
	file *manifest.FileMetadata, opts *IterOptions, bytesIterated *uint64,
) (internalIterator, internalIterator, error)

// levelIter provides a merged view of the sstables in a level.
//
// levelIter is used during compaction and as part of the Iterator
// implementation. When used as part of the Iterator implementation, level
// iteration needs to "pause" at sstable boundaries if a range deletion
// tombstone is the source of that boundary. We know if a range tombstone is
// the smallest or largest key in a file because the kind will be
// InternalKeyKindRangeDeletion. If the boundary key is a range deletion
// tombstone, we materialize a fake entry to return from levelIter. This
// prevents mergingIter from advancing past the sstable until the sstable
// contains the smallest (or largest for reverse iteration) key in the merged
// heap. Note that mergingIter treats a range deletion tombstone returned by
// the point iterator as a no-op.
//
// SeekPrefixGE presents the need for a second type of pausing. If an sstable
// iterator returns "not found" for a SeekPrefixGE operation, we don't want to
// advance to the next sstable as the "not found" does not indicate that all of
// the keys in the sstable are less than the search key. Advancing to the next
// sstable would cause us to skip over range tombstones, violating
// correctness. Instead, SeekPrefixGE creates a synthetic boundary key with the
// kind InternalKeyKindRangeDeletion which will be used to pause the levelIter
// at the sstable until the mergingIter is ready to advance past it.
type levelIter struct {
	logger Logger
	cmp    Compare
	split  Split
	// The lower/upper bounds for iteration as specified at creation or the most
	// recent call to SetBounds.
	lower []byte
	upper []byte
	// The iterator options for the currently open table. If
	// tableOpts.{Lower,Upper}Bound are nil, the corresponding iteration boundary
	// does not lie within the table bounds.
	tableOpts IterOptions
	// The LSM level this levelIter is initialized for.
	level manifest.Level
	// The keys to return when iterating past an sstable boundary and that
	// boundary is a range deletion tombstone. The boundary could be smallest
	// (i.e. arrived at with Prev), or largest (arrived at with Next).
	smallestBoundary *InternalKey
	largestBoundary  *InternalKey
	// A synthetic boundary key to return when SeekPrefixGE finds an sstable
	// which doesn't contain the search key, but which does contain range
	// tombstones.
	syntheticBoundary InternalKey
	// The iter for the current file. It is nil under any of the following conditions:
	// - files.Current() == nil
	// - err != nil
	// - some other constraint, like the bounds in opts, caused the file at index to not
	//   be relevant to the iteration.
	iter     internalIterator
	iterFile *fileMetadata
	newIters tableNewIters
	// When rangeDelIterPtr != nil, the caller requires that *rangeDelIterPtr must
	// point to a range del iterator corresponding to the current file. When this
	// iterator returns nil, *rangeDelIterPtr should also be set to nil. Whenever
	// a non-nil internalIterator is placed in rangeDelIterPtr, a copy is placed
	// in rangeDelIterCopy. This is done for the following special case:
	// when this iterator returns nil because of exceeding the bounds, we don't
	// close iter and *rangeDelIterPtr since we could reuse it in the next seek. But
	// we need to set *rangeDelIterPtr to nil because of the aforementioned contract.
	// This copy is used to revive the *rangeDelIterPtr in the case of reuse.
	rangeDelIterPtr  *internalIterator
	rangeDelIterCopy internalIterator
	files            manifest.LevelIterator
	err              error

	// Pointer into this level's entry in `mergingIterLevel::smallestUserKey,largestUserKey`.
	// We populate it with the corresponding bounds for the currently opened file. It is used for
	// two purposes (described for forward iteration. The explanation for backward iteration is
	// similar.)
	// - To limit the optimization that seeks lower-level iterators past keys shadowed by a range
	//   tombstone. Limiting this seek to the file largestUserKey is necessary since
	//   range tombstones are stored untruncated, while they only apply to keys within their
	//   containing file's boundaries. For a detailed example, see comment above `mergingIter`.
	// - To constrain the tombstone to act-within the bounds of the sstable when checking
	//   containment. For forward iteration we need the smallestUserKey.
	//
	// An example is sstable bounds [c#8, g#12] containing a tombstone [b, i)#7.
	// - When doing a SeekGE to user key X, the levelIter is at this sstable because X is either within
	//   the sstable bounds or earlier than the start of the sstable (and there is no sstable in
	//   between at this level). If X >= smallestUserKey, and the tombstone [b, i) contains X,
	//   it is correct to SeekGE the sstables at lower levels to min(g, i) (i.e., min of
	//   largestUserKey, tombstone.End) since any user key preceding min(g, i) must be covered by this
	//   tombstone (since it cannot have a version younger than this tombstone as it is at a lower
	//   level). And even if X = smallestUserKey or equal to the start user key of the tombstone,
	//   if the above conditions are satisfied we know that the internal keys corresponding to X at
	//   lower levels must have a version smaller than that in this file (again because of the level
	//   argument). So we don't need to use sequence numbers for this comparison.
	// - When checking whether this tombstone deletes internal key X we know that the levelIter is at this
	//   sstable so (repeating the above) X.UserKey is either within the sstable bounds or earlier than the
	//   start of the sstable (and there is no sstable in between at this level).
	//   - X is at at a lower level. If X.UserKey >= smallestUserKey, and the tombstone contains
	//     X.UserKey, we know X is deleted. This argument also works when X is a user key (we use
	//     it when seeking to test whether a user key is deleted).
	//   - X is at the same level. X must be within the sstable bounds of the tombstone so the
	//     X.UserKey >= smallestUserKey comparison is trivially true. In addition to the tombstone containing
	//     X we need to compare the sequence number of X and the tombstone (we don't need to look
	//     at how this tombstone is truncated to act-within the file bounds, which are InternalKeys,
	//     since X and the tombstone are from the same file).
	//
	// Iterating backwards has one more complication when checking whether a tombstone deletes
	// internal key X at a lower level (the construction we do here also works for a user key X).
	// Consider sstable bounds [c#8, g#InternalRangeDelSentinel] containing a tombstone [b, i)#7.
	// If we are positioned at key g#10 at a lower sstable, the tombstone we will see is [b, i)#7,
	// since the higher sstable is positioned at a key <= g#10. We should not use this tombstone
	// to delete g#10. This requires knowing that the largestUserKey is a range delete sentinel,
	// which we set in a separate bool below.
	//
	// These fields differs from the `*Boundary` fields in a few ways:
	// - `*Boundary` is only populated when the iterator is positioned exactly on the sentinel key.
	// - `*Boundary` can hold either the lower- or upper-bound, depending on the iterator direction.
	// - `*Boundary` is not exposed to the next higher-level iterator, i.e., `mergingIter`.
	smallestUserKey, largestUserKey  *[]byte
	isLargestUserKeyRangeDelSentinel *bool

	// Set to true iff the key returned by this iterator is a synthetic key
	// derived from the iterator bounds. This is used to prevent the
	// mergingIter from being stuck at such a synthetic key if it becomes the
	// top element of the heap.
	isSyntheticIterBoundsKey *bool

	// bytesIterated keeps track of the number of bytes iterated during compaction.
	bytesIterated *uint64

	// Disable invariant checks even if they are otherwise enabled. Used by tests
	// which construct "impossible" situations (e.g. seeking to a key before the
	// lower bound).
	disableInvariants bool
}

// levelIter implements the base.InternalIterator interface.
var _ base.InternalIterator = (*levelIter)(nil)

// newLevelIter returns a levelIter. It is permissible to pass a nil split
// parameter if the caller is never going to call SeekPrefixGE.
func newLevelIter(
	opts IterOptions,
	cmp Compare,
	split Split,
	newIters tableNewIters,
	files manifest.LevelIterator,
	level manifest.Level,
	bytesIterated *uint64,
) *levelIter {
	l := &levelIter{}
	l.init(opts, cmp, split, newIters, files, level, bytesIterated)
	return l
}

func (l *levelIter) init(
	opts IterOptions,
	cmp Compare,
	split Split,
	newIters tableNewIters,
	files manifest.LevelIterator,
	level manifest.Level,
	bytesIterated *uint64,
) {
	l.err = nil
	l.level = level
	l.logger = opts.getLogger()
	l.lower = opts.LowerBound
	l.upper = opts.UpperBound
	l.tableOpts.TableFilter = opts.TableFilter
	l.cmp = cmp
	l.split = split
	l.iterFile = nil
	l.newIters = newIters
	l.files = files
	l.bytesIterated = bytesIterated
}

func (l *levelIter) initRangeDel(rangeDelIter *internalIterator) {
	l.rangeDelIterPtr = rangeDelIter
}

func (l *levelIter) initSmallestLargestUserKey(
	smallestUserKey, largestUserKey *[]byte, isLargestUserKeyRangeDelSentinel *bool,
) {
	l.smallestUserKey = smallestUserKey
	l.largestUserKey = largestUserKey
	l.isLargestUserKeyRangeDelSentinel = isLargestUserKeyRangeDelSentinel
}

func (l *levelIter) initIsSyntheticIterBoundsKey(isSyntheticIterBoundsKey *bool) {
	l.isSyntheticIterBoundsKey = isSyntheticIterBoundsKey
}

func (l *levelIter) findFileGE(key []byte) *fileMetadata {
	// Find the earliest file whose largest key is >= ikey.
	//
	// If the earliest file has its largest key == ikey and that largest key is a
	// range deletion sentinel, we know that we manufactured this sentinel to convert
	// the exclusive range deletion end key into an inclusive key (reminder: [start, end)#seqnum
	// is the form of a range deletion sentinel which can contribute a largest key = end#sentinel).
	// In this case we don't return this as the earliest file since there is nothing actually
	// equal to key in it.
	//
	// Additionally, this prevents loading untruncated range deletions from a table which can't
	// possibly contain the target key and is required for correctness by mergingIter.SeekGE
	// (see the comment in that function).

	m := l.files.SeekGE(l.cmp, key)
	for m != nil && m.Largest.Trailer == InternalKeyRangeDeleteSentinel &&
		l.cmp(m.Largest.UserKey, key) == 0 {
		m = l.files.Next()
	}
	return m
}

func (l *levelIter) findFileLT(key []byte) *fileMetadata {
	// Find the last file whose smallest key is < ikey.
	return l.files.SeekLT(l.cmp, key)
}

// Init the iteration bounds for the current table. Returns -1 if the table
// lies fully before the lower bound, +1 if the table lies fully after the
// upper bound, and 0 if the table overlaps the the iteration bounds.
func (l *levelIter) initTableBounds(f *fileMetadata) int {
	l.tableOpts.LowerBound = l.lower
	if l.tableOpts.LowerBound != nil {
		if l.cmp(f.Largest.UserKey, l.tableOpts.LowerBound) < 0 {
			// The largest key in the sstable is smaller than the lower bound.
			return -1
		}
		if l.cmp(l.tableOpts.LowerBound, f.Smallest.UserKey) <= 0 {
			// The lower bound is smaller or equal to the smallest key in the
			// table. Iteration within the table does not need to check the lower
			// bound.
			l.tableOpts.LowerBound = nil
		}
	}
	l.tableOpts.UpperBound = l.upper
	if l.tableOpts.UpperBound != nil {
		if l.cmp(f.Smallest.UserKey, l.tableOpts.UpperBound) >= 0 {
			// The smallest key in the sstable is greater than or equal to the upper
			// bound.
			return 1
		}
		if l.cmp(l.tableOpts.UpperBound, f.Largest.UserKey) > 0 {
			// The upper bound is greater than the largest key in the
			// table. Iteration within the table does not need to check the upper
			// bound. NB: tableOpts.UpperBound is exclusive and f.Largest is inclusive.
			l.tableOpts.UpperBound = nil
		}
	}
	return 0
}

type loadFileReturnIndicator int8

const (
	noFileLoaded loadFileReturnIndicator = iota
	fileAlreadyLoaded
	newFileLoaded
)

func (l *levelIter) loadFile(file *fileMetadata, dir int) loadFileReturnIndicator {
	l.smallestBoundary = nil
	l.largestBoundary = nil
	if l.isSyntheticIterBoundsKey != nil {
		*l.isSyntheticIterBoundsKey = false
	}
	if l.iterFile == file {
		if l.err != nil {
			return noFileLoaded
		}
		if l.iter != nil {
			// We don't bother comparing the file bounds with the iteration bounds when we have
			// an already open iterator. It is possible that the iter may not be relevant given the
			// current iteration bounds, but it knows those bounds, so it will enforce them.
			if l.rangeDelIterPtr != nil {
				*l.rangeDelIterPtr = l.rangeDelIterCopy
			}
			return fileAlreadyLoaded
		}
		// We were already at file, but don't have an iterator, probably because the file was
		// beyond the iteration bounds. It may still be, but it is also possible that the bounds
		// have changed. We handle that below.
	}

	// Close both iter and rangeDelIterPtr. While mergingIter knows about
	// rangeDelIterPtr, it can't call Close() on it because it does not know
	// when the levelIter will switch it. Note that levelIter.Close() can be
	// called multiple times.
	if err := l.Close(); err != nil {
		return noFileLoaded
	}

	for {
		l.iterFile = file
		if file == nil {
			return noFileLoaded
		}

		switch l.initTableBounds(file) {
		case -1:
			// The largest key in the sstable is smaller than the lower bound.
			if dir < 0 {
				return noFileLoaded
			}
			file = l.files.Next()
			continue
		case +1:
			// The smallest key in the sstable is greater than or equal to the upper
			// bound.
			if dir > 0 {
				return noFileLoaded
			}
			file = l.files.Prev()
			continue
		}

		var rangeDelIter internalIterator
		l.iter, rangeDelIter, l.err = l.newIters(l.files.Current(), &l.tableOpts, l.bytesIterated)
		if l.err != nil {
			return noFileLoaded
		}
		if l.rangeDelIterPtr != nil {
			*l.rangeDelIterPtr = rangeDelIter
			l.rangeDelIterCopy = rangeDelIter
		} else if rangeDelIter != nil {
			rangeDelIter.Close()
		}
		if l.smallestUserKey != nil {
			*l.smallestUserKey = file.Smallest.UserKey
		}
		if l.largestUserKey != nil {
			*l.largestUserKey = file.Largest.UserKey
		}
		if l.isLargestUserKeyRangeDelSentinel != nil {
			*l.isLargestUserKeyRangeDelSentinel = file.Largest.Trailer == InternalKeyRangeDeleteSentinel
		}
		return newFileLoaded
	}
}

// In race builds we verify that the keys returned by levelIter lie within
// [lower,upper).
func (l *levelIter) verify(key *InternalKey, val []byte) (*InternalKey, []byte) {
	// Note that invariants.Enabled is a compile time constant, which means the
	// block of code will be compiled out of normal builds making this method
	// eligible for inlining. Do not change this to use a variable.
	if invariants.Enabled && !l.disableInvariants && key != nil {
		// We allow returning a boundary key that is outside of the lower/upper
		// bounds as such keys are always range tombstones which will be skipped by
		// the Iterator.
		if l.lower != nil && key != l.smallestBoundary && l.cmp(key.UserKey, l.lower) < 0 {
			l.logger.Fatalf("levelIter %s: lower bound violation: %s < %s\n%s", l.level, key, l.lower, debug.Stack())
		}
		if l.upper != nil && key != l.largestBoundary && l.cmp(key.UserKey, l.upper) > 0 {
			l.logger.Fatalf("levelIter %s: upper bound violation: %s > %s\n%s", l.level, key, l.upper, debug.Stack())
		}
	}
	return key, val
}

func (l *levelIter) SeekGE(key []byte) (*InternalKey, []byte) {
	l.err = nil // clear cached iteration error
	if l.isSyntheticIterBoundsKey != nil {
		*l.isSyntheticIterBoundsKey = false
	}

	// NB: the top-level Iterator has already adjusted key based on
	// IterOptions.LowerBound.
	if l.loadFile(l.findFileGE(key), +1) == noFileLoaded {
		return nil, nil
	}
	if ikey, val := l.iter.SeekGE(key); ikey != nil {
		return l.verify(ikey, val)
	}
	return l.verify(l.skipEmptyFileForward())
}

func (l *levelIter) SeekPrefixGE(
	prefix, key []byte, trySeekUsingNext bool,
) (*base.InternalKey, []byte) {
	l.err = nil // clear cached iteration error
	if l.isSyntheticIterBoundsKey != nil {
		*l.isSyntheticIterBoundsKey = false
	}

	// NB: the top-level Iterator has already adjusted key based on
	// IterOptions.LowerBound.
	loadFileIndicator := l.loadFile(l.findFileGE(key), +1)
	if loadFileIndicator == noFileLoaded {
		return nil, nil
	}
	if loadFileIndicator == newFileLoaded {
		// File changed, so l.iter has changed, and that iterator is not
		// positioned appropriately.
		trySeekUsingNext = false
	}
	if key, val := l.iter.SeekPrefixGE(prefix, key, trySeekUsingNext); key != nil {
		return l.verify(key, val)
	}
	// When SeekPrefixGE returns nil, we have not necessarily reached the end of
	// the sstable. All we know is that a key with prefix does not exist in the
	// current sstable. We do know that the key lies within the bounds of the
	// table as findFileGE found the table where key <= meta.Largest. We treat
	// this case the same as SeekGE where an upper-bound resides within the
	// sstable and generate a synthetic boundary key.
	if l.rangeDelIterPtr != nil && *l.rangeDelIterPtr != nil {
		if l.tableOpts.UpperBound != nil {
			l.syntheticBoundary.UserKey = l.tableOpts.UpperBound
			l.syntheticBoundary.Trailer = InternalKeyRangeDeleteSentinel
			l.largestBoundary = &l.syntheticBoundary
			if l.isSyntheticIterBoundsKey != nil {
				*l.isSyntheticIterBoundsKey = true
			}
			return l.verify(l.largestBoundary, nil)
		}
		l.syntheticBoundary = l.iterFile.Largest
		l.syntheticBoundary.SetKind(InternalKeyKindRangeDelete)
		l.largestBoundary = &l.syntheticBoundary
		if l.isSyntheticIterBoundsKey != nil {
			*l.isSyntheticIterBoundsKey = false
		}
		return l.verify(l.largestBoundary, nil)
	}
	// It is possible that we are here because bloom filter matching failed.
	// In that case it is likely that all keys matching the prefix are wholly
	// within the current file and cannot be in the subsequent file. In that
	// case we don't want to go to the next file, since loading and seeking in
	// there has some cost. Additionally, for sparse key spaces, loading the
	// next file will defeat the optimization for the next SeekPrefixGE that
	// is called with trySeekUsingNext=true, since for sparse key spaces it is
	// likely that the next key will also be contained in the current file.
	if n := l.split(l.iterFile.Largest.UserKey); l.cmp(prefix, l.iterFile.Largest.UserKey[:n]) < 0 {
		return nil, nil
	}
	return l.verify(l.skipEmptyFileForward())
}

func (l *levelIter) SeekLT(key []byte) (*InternalKey, []byte) {
	l.err = nil // clear cached iteration error
	if l.isSyntheticIterBoundsKey != nil {
		*l.isSyntheticIterBoundsKey = false
	}

	// NB: the top-level Iterator has already adjusted key based on
	// IterOptions.UpperBound.
	if l.loadFile(l.findFileLT(key), -1) == noFileLoaded {
		return nil, nil
	}
	if key, val := l.iter.SeekLT(key); key != nil {
		return l.verify(key, val)
	}
	return l.verify(l.skipEmptyFileBackward())
}

func (l *levelIter) First() (*InternalKey, []byte) {
	l.err = nil // clear cached iteration error
	if l.isSyntheticIterBoundsKey != nil {
		*l.isSyntheticIterBoundsKey = false
	}

	// NB: the top-level Iterator will call SeekGE if IterOptions.LowerBound is
	// set.
	if l.loadFile(l.files.First(), +1) == noFileLoaded {
		return nil, nil
	}
	if key, val := l.iter.First(); key != nil {
		return l.verify(key, val)
	}
	return l.verify(l.skipEmptyFileForward())
}

func (l *levelIter) Last() (*InternalKey, []byte) {
	l.err = nil // clear cached iteration error
	if l.isSyntheticIterBoundsKey != nil {
		*l.isSyntheticIterBoundsKey = false
	}

	// NB: the top-level Iterator will call SeekLT if IterOptions.UpperBound is
	// set.
	if l.loadFile(l.files.Last(), -1) == noFileLoaded {
		return nil, nil
	}
	if key, val := l.iter.Last(); key != nil {
		return l.verify(key, val)
	}
	return l.verify(l.skipEmptyFileBackward())
}

func (l *levelIter) Next() (*InternalKey, []byte) {
	if l.err != nil || l.iter == nil {
		return nil, nil
	}
	if l.isSyntheticIterBoundsKey != nil {
		*l.isSyntheticIterBoundsKey = false
	}

	switch {
	case l.largestBoundary != nil:
		if l.tableOpts.UpperBound != nil {
			// The UpperBound was within this file, so don't load the next
			// file. We leave the largestBoundary unchanged so that subsequent
			// calls to Next() stay at this file. If a Seek/First/Last call is
			// made and this file continues to be relevant, loadFile() will
			// set the largestBoundary to nil.
			if l.rangeDelIterPtr != nil {
				*l.rangeDelIterPtr = nil
			}
			return nil, nil
		}
		// We're stepping past the boundary key, so now we can load the next file.
		if l.loadFile(l.files.Next(), +1) != noFileLoaded {
			if key, val := l.iter.First(); key != nil {
				return l.verify(key, val)
			}
			return l.verify(l.skipEmptyFileForward())
		}
		return nil, nil

	default:
		// Reset the smallest boundary since we're moving away from it.
		l.smallestBoundary = nil
		if key, val := l.iter.Next(); key != nil {
			return l.verify(key, val)
		}
	}
	return l.verify(l.skipEmptyFileForward())
}

func (l *levelIter) Prev() (*InternalKey, []byte) {
	if l.err != nil || l.iter == nil {
		return nil, nil
	}
	if l.isSyntheticIterBoundsKey != nil {
		*l.isSyntheticIterBoundsKey = false
	}

	switch {
	case l.smallestBoundary != nil:
		if l.tableOpts.LowerBound != nil {
			// The LowerBound was within this file, so don't load the previous
			// file. We leave the smallestBoundary unchanged so that
			// subsequent calls to Prev() stay at this file. If a
			// Seek/First/Last call is made and this file continues to be
			// relevant, loadFile() will set the smallestBoundary to nil.
			if l.rangeDelIterPtr != nil {
				*l.rangeDelIterPtr = nil
			}
			return nil, nil
		}
		// We're stepping past the boundary key, so now we can load the prev file.
		if l.loadFile(l.files.Prev(), -1) != noFileLoaded {
			if key, val := l.iter.Last(); key != nil {
				return l.verify(key, val)
			}
			return l.verify(l.skipEmptyFileBackward())
		}
		return nil, nil

	default:
		// Reset the largest boundary since we're moving away from it.
		l.largestBoundary = nil
		if key, val := l.iter.Prev(); key != nil {
			return l.verify(key, val)
		}
	}
	return l.verify(l.skipEmptyFileBackward())
}

func (l *levelIter) skipEmptyFileForward() (*InternalKey, []byte) {
	var key *InternalKey
	var val []byte
	// The first iteration of this loop starts with an already exhausted
	// l.iter. The reason for the exhaustion is either that we iterated to the
	// end of the sstable, or our iteration was terminated early due to the
	// presence of an upper-bound or the use of SeekPrefixGE. If
	// l.rangeDelIterPtr is non-nil, we may need to pretend the iterator is
	// not exhausted to allow for the merging to finish consuming the
	// l.rangeDelIterPtr before levelIter switches the rangeDelIter from
	// under it. This pretense is done by either generating a synthetic
	// boundary key or returning the largest key of the file, depending on the
	// exhaustion reason.

	// Subsequent iterations will examine consecutive files such that the first
	// file that does not have an exhausted iterator causes the code to return
	// that key, else the behavior described above if there is a corresponding
	// rangeDelIterPtr.
	for ; key == nil; key, val = l.iter.First() {
		if l.rangeDelIterPtr != nil {
			// We're being used as part of a mergingIter and we've exhausted the
			// current sstable. If an upper bound is present and the upper bound lies
			// within the current sstable, then we will have reached the upper bound
			// rather than the end of the sstable. We need to return a synthetic
			// boundary key so that mergingIter can use the range tombstone iterator
			// until the other levels have reached this boundary.
			//
			// It is safe to set the boundary key to the UpperBound user key
			// with the RANGEDEL sentinel since it is the smallest InternalKey
			// that matches the exclusive upper bound, and does not represent
			// a real key.
			if l.tableOpts.UpperBound != nil {
				if *l.rangeDelIterPtr != nil {
					l.syntheticBoundary.UserKey = l.tableOpts.UpperBound
					l.syntheticBoundary.Trailer = InternalKeyRangeDeleteSentinel
					l.largestBoundary = &l.syntheticBoundary
					if l.isSyntheticIterBoundsKey != nil {
						*l.isSyntheticIterBoundsKey = true
					}
					return l.largestBoundary, nil
				}
				// Else there are no range deletions in this sstable. This
				// helps with performance when many levels are populated with
				// sstables and most don't have any actual keys within the
				// bounds.
				return nil, nil
			}
			// If the boundary is a range deletion tombstone, return that key.
			if l.iterFile.Largest.Kind() == InternalKeyKindRangeDelete {
				l.largestBoundary = &l.iterFile.Largest
				return l.largestBoundary, nil
			}
		}

		// Current file was exhausted. Move to the next file.
		if l.loadFile(l.files.Next(), +1) == noFileLoaded {
			return nil, nil
		}
	}
	return key, val
}

func (l *levelIter) skipEmptyFileBackward() (*InternalKey, []byte) {
	var key *InternalKey
	var val []byte
	// The first iteration of this loop starts with an already exhausted
	// l.iter. The reason for the exhaustion is either that we iterated to the
	// end of the sstable, or our iteration was terminated early due to the
	// presence of a lower-bound. If l.rangeDelIterPtr is non-nil, we may need
	// to pretend the iterator is not exhausted to allow for the merging to
	// finish consuming the l.rangeDelIterPtr before levelIter switches the
	// rangeDelIter from under it. This pretense is done by either generating
	// a synthetic boundary key or returning the smallest key of the file,
	// depending on the exhaustion reason.

	// Subsequent iterations will examine consecutive files such that the first
	// file that does not have an exhausted iterator causes the code to return
	// that key, else the behavior described above if there is a corresponding
	// rangeDelIterPtr.
	for ; key == nil; key, val = l.iter.Last() {
		if l.rangeDelIterPtr != nil {
			// We're being used as part of a mergingIter and we've exhausted the
			// current sstable. If a lower bound is present and the lower bound lies
			// within the current sstable, then we will have reached the lower bound
			// rather than the beginning of the sstable. We need to return a
			// synthetic boundary key so that mergingIter can use the range tombstone
			// iterator until the other levels have reached this boundary.
			//
			// It is safe to set the boundary key to the LowerBound user key
			// with the RANGEDEL sentinel since it is the smallest InternalKey
			// that is within the inclusive lower bound, and does not
			// represent a real key.
			if l.tableOpts.LowerBound != nil {
				if *l.rangeDelIterPtr != nil {
					l.syntheticBoundary.UserKey = l.tableOpts.LowerBound
					l.syntheticBoundary.Trailer = InternalKeyRangeDeleteSentinel
					l.smallestBoundary = &l.syntheticBoundary
					if l.isSyntheticIterBoundsKey != nil {
						*l.isSyntheticIterBoundsKey = true
					}
					return l.smallestBoundary, nil
				}
				// Else there are no range deletions in this sstable. This
				// helps with performance when many levels are populated with
				// sstables and most don't have any actual keys within the
				// bounds.
				return nil, nil
			}
			// If the boundary is a range deletion tombstone, return that key.
			if l.iterFile.Smallest.Kind() == InternalKeyKindRangeDelete {
				l.smallestBoundary = &l.iterFile.Smallest
				return l.smallestBoundary, nil
			}
		}

		// Current file was exhausted. Move to the previous file.
		if l.loadFile(l.files.Prev(), -1) == noFileLoaded {
			return nil, nil
		}
	}
	return key, val
}

func (l *levelIter) Error() error {
	if l.err != nil || l.iter == nil {
		return l.err
	}
	return l.iter.Error()
}

func (l *levelIter) Close() error {
	if l.iter != nil {
		l.err = l.iter.Close()
		l.iter = nil
	}
	if l.rangeDelIterPtr != nil {
		if t := l.rangeDelIterCopy; t != nil {
			l.err = firstError(l.err, t.Close())
		}
		*l.rangeDelIterPtr = nil
		l.rangeDelIterCopy = nil
	}
	return l.err
}

func (l *levelIter) SetBounds(lower, upper []byte) {
	l.lower = lower
	l.upper = upper

	if l.iter == nil {
		return
	}

	// Update tableOpts.{Lower,Upper}Bound in case the new boundaries fall within
	// the boundaries of the current table.
	if l.initTableBounds(l.iterFile) != 0 {
		// The table does not overlap the bounds. Close() will set levelIter.err if
		// an error occurs.
		_ = l.Close()
		return
	}

	l.iter.SetBounds(l.tableOpts.LowerBound, l.tableOpts.UpperBound)
}

func (l *levelIter) String() string {
	if l.iterFile != nil {
		return fmt.Sprintf("%s: fileNum=%s", l.level, l.iter.String())
	}
	return fmt.Sprintf("%s: fileNum=<nil>", l.level)
}
